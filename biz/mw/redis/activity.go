package redis

import (
	"encoding/json"
	"time"

	"github.com/authboot/authboot-server/pkg/constants"
	"github.com/authboot/authboot-server/pkg/geoip"
)

// TouchUser gates before resolving GeoIP, and patches only activity in the live
// record. Neither refresh credentials nor the session TTL are written from Go.
func (SessionStore) TouchUser(org, user int64, sid, ip string) (*SessionRecord, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	key := sessionKey(constants.UserSubject, sid)
	gate := key + ":activity"
	raw, err := rdbSession.Eval(`
local raw = redis.call('GET', KEYS[1])
if not raw then return '' end
local r = cjson.decode(raw)
if tostring(r.organization_id) ~= ARGV[1] or tostring(r.account_id) ~= ARGV[2] then return '' end
if not redis.call('SET', KEYS[2], '1', 'NX', 'EX', 300) then return '' end
return raw`, []string{key, gate}, org, user).Text()
	if err != nil || raw == "" {
		return nil, err
	}
	var rec SessionRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		return nil, err
	}
	location := rec.LastActiveLocation
	if rec.LastActiveIP != ip {
		location = geoip.Resolve(ip)
	}
	encoded, err := json.Marshal(location)
	if err != nil {
		return nil, err
	}
	raw, err = rdbSession.Eval(`
local raw = redis.call('GET', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
if not raw or ttl <= 0 then return '' end
local r = cjson.decode(raw)
if tostring(r.organization_id) ~= ARGV[1] or tostring(r.account_id) ~= ARGV[2] then return '' end
r.last_active_at = tonumber(ARGV[3])
r.last_active_ip = ARGV[4]
r.last_active_location = cjson.decode(ARGV[5])
local updated = cjson.encode(r)
redis.call('SET', KEYS[1], updated, 'PX', ttl)
return updated`, []string{key}, org, user, time.Now().Unix(), ip, string(encoded)).Text()
	if err != nil || raw == "" {
		return nil, err
	}
	err = json.Unmarshal([]byte(raw), &rec)
	return &rec, err
}

// RevokeUserSelection is linearized with Create/Rotate by one Redis script.
// keep must be the authenticated session, never a request-provided exception.
// mode is others, device or session. New logins after the script remain valid.
func (SessionStore) RevokeUserSelection(org, user int64, keep, mode, target string) ([]string, error) {
	if rdbSession == nil {
		return nil, ErrSessionStoreUnavailable
	}
	if keep == "" || (mode != "others" && mode != "device" && mode != "session") || (mode != "others" && target == "") {
		return nil, ErrSessionNotFound
	}
	result, err := rdbSession.Eval(`
local current = redis.call('GET', KEYS[2])
if not current then return redis.error_reply('current session missing') end
local c = cjson.decode(current)
if tostring(c.organization_id) ~= ARGV[1] or tostring(c.account_id) ~= ARGV[2] then return redis.error_reply('owner mismatch') end
local out = {}
for _,sid in ipairs(redis.call('SMEMBERS', KEYS[1])) do
 local key = ARGV[6] .. sid
 local raw = redis.call('GET', key)
 if raw then
  local r = cjson.decode(raw)
  local selected = (ARGV[4] == 'others' and sid ~= ARGV[3]) or (ARGV[4] == 'device' and r.device_id == ARGV[5]) or (ARGV[4] == 'session' and sid == ARGV[5])
  if selected and tostring(r.organization_id) == ARGV[1] and tostring(r.account_id) == ARGV[2] then
   redis.call('DEL', key, ARGV[7] .. r.refresh_token)
   redis.call('SREM', KEYS[1], sid)
   table.insert(out,sid)
  end
 end
end
return out`, []string{userSessionsKey(constants.UserSubject, user), sessionKey(constants.UserSubject, keep)},
		org, user, keep, mode, target, sessionKey(constants.UserSubject, ""), refreshKey(constants.UserSubject, "")).Result()
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, value := range result.([]interface{}) {
		ids = append(ids, value.(string))
	}
	return ids, nil
}
