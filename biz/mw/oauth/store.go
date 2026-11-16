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

package oauth

import (
	"context"
	"fmt"

	"github.com/authboot/authboot-server/biz/dal/db"
)

// ConfigStore supplies a provider's config for a given organization. Load
// returns the DECRYPTED vendor JSON (the shape of provider.WechatConfig et al.)
// for (orgID, provider), or an error when the config is absent/disabled.
//
// The oauth facade decodes the returned JSON into the concrete vendor config,
// so a store only has to answer "give me org N's raw config for provider X".
type ConfigStore interface {
	Load(ctx context.Context, orgID int64, provider string) ([]byte, error)
}

// dbStore is the production ConfigStore: it reads the oauth_configs table and
// decrypts the config blob.
type dbStore struct{}

// NewDBStore returns a ConfigStore backed by the oauth_configs table. Requires
// OAUTH_CONFIG_KEY to be set (see crypto.go) so blobs can be decrypted.
func NewDBStore() ConfigStore { return dbStore{} }

func (dbStore) Load(_ context.Context, orgID int64, provider string) ([]byte, error) {
	row, err := db.IOAuthConfigDAO.QueryOAuthConfig(orgID, provider)
	if err != nil {
		return nil, fmt.Errorf("oauth: load config (org=%d provider=%s): %w", orgID, provider, err)
	}
	plain, err := decrypt(row.Config)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// MapStore is an in-memory ConfigStore for tests and local runs without a
// database. Keys are (orgID, provider); values are the plaintext vendor JSON.
type MapStore struct {
	m map[string][]byte
}

// NewMapStore builds an empty in-memory store.
func NewMapStore() *MapStore { return &MapStore{m: map[string][]byte{}} }

// Set registers the plaintext config JSON for (orgID, provider).
func (s *MapStore) Set(orgID int64, provider string, configJSON []byte) {
	s.m[mapKey(orgID, provider)] = configJSON
}

func (s *MapStore) Load(_ context.Context, orgID int64, provider string) ([]byte, error) {
	b, ok := s.m[mapKey(orgID, provider)]
	if !ok {
		return nil, fmt.Errorf("oauth: no config for org=%d provider=%s", orgID, provider)
	}
	return b, nil
}

func mapKey(orgID int64, provider string) string {
	return fmt.Sprintf("%d:%s", orgID, provider)
}
