package redis

import "time"

// CaptchaStore shares image answers between replicas. Get(clear=true) is atomic.
type CaptchaStore struct{ TTL time.Duration }

func (s CaptchaStore) Set(id, value string) {
	_ = (Code{}).Store("captcha_image", id, value, s.TTL)
}

func (s CaptchaStore) Get(id string, clear bool) string {
	if rdbCode == nil {
		return ""
	}
	key := codeKey("captcha_image", id)
	if !clear {
		value, _ := rdbCode.Get(key).Result()
		return value
	}
	value, _ := rdbCode.Eval(`local v = redis.call('GET', KEYS[1]); redis.call('DEL', KEYS[1]); return v`, []string{key}).Text()
	return value
}

func (s CaptchaStore) Verify(id, answer string, clear bool) bool {
	value := s.Get(id, clear)
	return value != "" && answer != "" && value == answer
}
