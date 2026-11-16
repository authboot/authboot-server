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
	"strconv"
	"time"

	"github.com/go-redis/redis/v7"
)

// notificationLatestSuffix keys the per-user "latest notification id" pointer.
const notificationLatestSuffix = ":notif_latest"

// notificationLatestTTL bounds how long the latest-id pointer is cached. It is
// refreshed on every write; a long TTL keeps the polling fast path warm while
// still letting idle users' keys expire eventually.
const notificationLatestTTL = 30 * 24 * time.Hour

// Notification namespaces the notification polling cache helpers.
type Notification struct{}

// PollResult is the outcome of a lightweight "is there anything new?" check.
type PollResult struct {
	// HasNew reports whether the client should pull the notification list.
	HasNew bool
	// LatestID is the newest notification id known to the cache (0 if unknown).
	LatestID int64
	// Cached reports whether LatestID came from the cache. When false the
	// caller should fall back to the database, then call SetLatest to warm it.
	Cached bool
}

// notificationKey builds the redis key holding a user's latest notification id.
func notificationKey(userID int64) string {
	return strconv.FormatInt(userID, 10) + notificationLatestSuffix
}

// SetLatest caches the latest notification id for a user. Call this on the
// write path whenever a new notification is created for the user.
func (n Notification) SetLatest(userID, notificationID int64) error {
	if rdbNotification == nil {
		return nil
	}
	return rdbNotification.Set(notificationKey(userID), notificationID, notificationLatestTTL).Err()
}

// GetLatest returns the cached latest notification id for a user. The bool
// reports a cache hit; on a miss it returns (0, false, nil).
func (n Notification) GetLatest(userID int64) (int64, bool, error) {
	if rdbNotification == nil {
		return 0, false, nil
	}
	v, err := rdbNotification.Get(notificationKey(userID)).Int64()
	if err == redis.Nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return v, true, nil
}

// CheckNew implements the polling fast path: given the id the client last saw,
// it decides whether new notifications may exist without touching the database.
//
//   - cache hit + lastSeenID == latest -> HasNew=false (return "no new")
//   - cache hit + lastSeenID != latest -> HasNew=true, LatestID set (pull list)
//   - cache miss                       -> HasNew=true, Cached=false (DB fallback)
//
// On a cache miss the caller should query the database for the real latest id,
// return the list, and warm the cache via SetLatest.
func (n Notification) CheckNew(userID, lastSeenID int64) (PollResult, error) {
	latest, found, err := n.GetLatest(userID)
	if err != nil {
		return PollResult{}, err
	}
	if !found {
		return PollResult{HasNew: true, Cached: false}, nil
	}
	return PollResult{
		HasNew:   lastSeenID != latest,
		LatestID: latest,
		Cached:   true,
	}, nil
}

// DelLatest drops a user's cached latest-id pointer, forcing a DB fallback on
// the next poll. Useful after bulk operations that change the newest id.
func (n Notification) DelLatest(userID int64) error {
	if rdbNotification == nil {
		return nil
	}
	return rdbNotification.Del(notificationKey(userID)).Err()
}
