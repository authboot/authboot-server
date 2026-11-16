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

// codeKey builds the redis key holding the code for a scene (e.g. "login") and
// target (the email address or phone number the code was sent to).
func codeKey(scene, target string) string {
	return codeKeyPrefix + scene + ":" + target
}

// Store saves a verification code for the (scene, target) pair with the given
// TTL, overwriting any previous unexpired code. A no-op (nil) when redis is not
// initialized, so callers degrade gracefully in environments without redis.
func (Code) Store(scene, target, code string, ttl time.Duration) error {
	if rdbCode == nil {
		return nil
	}
	return rdbCode.Set(codeKey(scene, target), code, ttl).Err()
}

// Verify checks a submitted code against the stored one. On a match the code is
// consumed (deleted) so it cannot be reused, and true is returned. Any mismatch,
// expiry, missing code, or uninitialized redis yields false (fail closed).
func (Code) Verify(scene, target, code string) bool {
	if rdbCode == nil || code == "" {
		return false
	}
	key := codeKey(scene, target)
	stored, err := rdbCode.Get(key).Result()
	if err == redis.Nil || err != nil {
		return false
	}
	if stored != code {
		return false
	}
	rdbCode.Del(key)
	return true
}
