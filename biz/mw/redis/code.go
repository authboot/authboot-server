/*
 * Copyright 2023 CloudWeGo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package redis

import (
	"strings"
	"time"

	"github.com/go-redis/redis/v7"
)

// codeKeyPrefix namespaces one-time verification codes (email / SMS login) so
// they never collide with other keys sharing the codes database.
const codeKeyPrefix = "code:"

// Code namespaces the one-time verification-code store used by email / SMS
// login. A code is stored under a (scene, target) key with a TTL, then
// consumed on the first successful Verify to prevent replay.
type Code struct{}

// NormalizeCodeTarget canonicalizes contact addresses for delivery and code lookup.
// Phone numbers retain their explicit country prefix.
func NormalizeCodeTarget(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "@") {
		return strings.ToLower(target)
	}
	return target
}

// codeKey builds the redis key holding the code for a scene (e.g. "login") and
// target (the email address or phone number the code was sent to).
func codeKey(scene, target string) string {
	// Captcha grants use opaque, case-sensitive tokens rather than contacts.
	if scene != "captcha_grant" {
		target = NormalizeCodeTarget(target)
	}
	return codeKeyPrefix + scene + ":" + target
}

// Store saves a verification code for the (scene, target) pair with the given
// TTL, overwriting any previous unexpired code. Uninitialized Redis fails closed.
func (Code) Store(scene, target, code string, ttl time.Duration) error {
	if rdbCode == nil {
		return ErrSessionStoreUnavailable
	}
	return rdbCode.Eval(`
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('DEL', KEYS[2])
return 1`, []string{codeKey(scene, target), codeKey(scene, target) + ":attempts"}, code, ttl.Milliseconds()).Err()
}

// Verify checks a submitted code against the stored one. On a match the code is
// consumed (deleted) so it cannot be reused, and true is returned. Any mismatch,
// expiry, missing code, or uninitialized redis yields false (fail closed).
func (Code) Verify(scene, target, code string) bool {
	if rdbCode == nil || code == "" {
		return false
	}
	key := codeKey(scene, target)
	n, err := redis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
if value == ARGV[1] then
 redis.call('DEL', KEYS[1], KEYS[2])
 return 1
end
local attempts = redis.call('INCR', KEYS[2])
redis.call('PEXPIRE', KEYS[2], redis.call('PTTL', KEYS[1]))
if attempts >= 5 then redis.call('DEL', KEYS[1]) end
return 0`).Run(rdbCode, []string{key, key + ":attempts"}, code).Int()
	return err == nil && n == 1
}

// Discard removes only the failed delivery's code, never a later replacement.
func (Code) Discard(scene, target, code string) {
	if rdbCode != nil {
		rdbCode.Eval(`if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0`, []string{codeKey(scene, target)}, code)
	}
}

// Allow applies a fixed-window limit atomically and fails closed.
func (Code) Allow(key string, limit int, window time.Duration) bool {
	if rdbCode == nil {
		return false
	}
	n, err := rdbCode.Eval(`
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return n`, []string{"rate:" + key}, window.Milliseconds()).Int()
	return err == nil && n <= limit
}
