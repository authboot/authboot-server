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
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v7"
	"testing"
)

func initFollowTest(t *testing.T) {
	t.Helper()
	server := miniredis.RunT(t)
	t.Setenv("REDIS_ADDR", server.Addr())
	t.Setenv("REDIS_PASSWORD", "")
	InitRedis()
	t.Cleanup(func() {
		for _, client := range []*redis.Client{rdbFollows, rdbFavorite, rdbNotification, rdbCode, rdbSession} {
			_ = client.Close()
		}
	})
}

var rdb Follows

func TestFollows_AddFollow(t *testing.T) {
	initFollowTest(t)
	rdb.AddFollower(1001, 1002)
}

func TestFollows_AddFollower(t *testing.T) {
	initFollowTest(t)
	rdb.AddFollow(1002, 1001)
}
