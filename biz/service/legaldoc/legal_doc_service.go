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

// Package legaldoc implements the org legal-document version history, aligned
// with the dashboard's Legal panel: documents are immutable append-only
// version lists (publish appends, never edits); each version carries the
// public URL, a change summary, effective time, publisher, and an optional
// archived content snapshot with a SHA-256 hash as compliance evidence.
package legaldoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
	legaldoc "github.com/authboot/authboot-server/biz/model/legaldoc"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/biz/mw/legaldocs"
	"github.com/authboot/authboot-server/pkg/errno"
)

// Service assembles legal-doc read/write logic.
type Service struct {
	ctx context.Context
	c   *app.RequestContext

	versionDAO *db.OrganizationLegalDocVersionDAO
	orgDAO     *db.OrganizationDAO
}

// NewService creates a legal-doc service.
func NewService(ctx context.Context, c *app.RequestContext) *Service {
	return &Service{
		ctx:        ctx,
		c:          c,
		versionDAO: db.NewOrganizationLegalDocVersionDAO(db.DB),
		orgDAO:     db.IOrganizationDAO,
	}
}

// normalizeDocType validates and maps the requested doc type to its canonical
// stored name. The dashboard UI calls them terms / privacy; both spellings are
// accepted here so the BFF can pass through either.
func normalizeDocType(docType string) (string, error) {
	switch docType {
	case "terms", db.LegalDocTypeUserAgreement:
		return db.LegalDocTypeUserAgreement, nil
	case "privacy", db.LegalDocTypePrivacyPolicy:
		return db.LegalDocTypePrivacyPolicy, nil
	default:
		return "", errno.ParamErr
	}
}

// PublishLegalDoc appends one immutable version. effective_at == 0 publishes
// immediately (active, previous active retired); a future time schedules it.
func (s *Service) PublishLegalDoc(req *legaldoc.PublishLegalDocRequest) (*legaldoc.LegalVersion, error) {
	docType, err := normalizeDocType(req.DocType)
	if err != nil {
		return nil, err
	}
	if req.Url == "" || req.Changelog == "" {
		return nil, errno.ParamErr
	}
	if len(req.Url) > 512 || len(req.Changelog) > 512 {
		return nil, errno.ParamErr
	}
	if _, err := s.orgDAO.QueryOrganizationByID(req.OrganizationId); err != nil {
		return nil, err
	}

	// 归档快照：服务端发布时抓取 URL，存储实际下载到的字节并对其计算
	// SHA-256（前 16 hex）。发布者不再手工粘贴内容，杜绝"贴错文本"；
	// 抓取失败（URL 不可达 / 超限 / 内网地址）则整个发布失败，由发布者
	// 修正 URL 后重试——不允许"登记了哈希却拿不出原文"的版本存在。
	snapshot, err := legaldocs.FetchSnapshot(s.ctx, req.Url)
	if err != nil {
		hlog.CtxWarnf(s.ctx, "legal doc snapshot fetch failed for %s: %v", req.Url, err)
		return nil, errno.ParamErr
	}
	sum := sha256.Sum256(snapshot)
	contentHash := hex.EncodeToString(sum[:])[:16]
	hasSnapshot := true

	now := time.Now().Unix()
	effectiveAt := req.EffectiveAt
	if effectiveAt == 0 {
		effectiveAt = now
	}
	status := db.LegalVersionStatusScheduled
	if effectiveAt <= now {
		status = db.LegalVersionStatusActive
		effectiveAt = now
	}

	// 版本号分配 + 写入 + retire 旧 active 必须在一个事务里，保证任一时刻
	// (org, doc_type) 至多一个 active 版本。顺序很重要：先 retire 旧 active，
	// 再插入新版本——若反过来，"retire 所有 active" 会把刚插入的新版本也
	// 一起退役，导致没有任何 active 行。
	var published *db.OrganizationLegalDocVersion
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		txDAO := s.versionDAO.WithTx(tx)
		nextVersion, err := txDAO.NextVersion(req.OrganizationId, docType)
		if err != nil {
			return err
		}
		if status == db.LegalVersionStatusActive {
			if err := txDAO.RetireActiveVersions(req.OrganizationId, docType); err != nil {
				return err
			}
		}
		published = &db.OrganizationLegalDocVersion{
			OrganizationID: req.OrganizationId,
			DocType:        docType,
			Version:        nextVersion,
			URL:            req.Url,
			Changelog:      req.Changelog,
			Status:         status,
			EffectiveAt:    effectiveAt,
			PublishedBy:    s.currentPublisher(),
			PublishedAt:    now,
			ContentHash:    contentHash,
			HasSnapshot:    hasSnapshot,
			Content:        string(snapshot),
			CreatedAt:      now,
		}
		return txDAO.PublishVersion(published)
	})
	if err != nil {
		return nil, err
	}
	hlog.CtxInfof(s.ctx, "legal doc %s v%d published for org %d (status=%s)",
		docType, published.Version, req.OrganizationId, status)
	return toLegalVersion(published, false), nil
}

// ListLegalVersions returns an organization's full immutable history for one
// doc type, newest first. Content is never included in list responses.
func (s *Service) ListLegalVersions(req *legaldoc.ListLegalVersionsRequest) ([]*legaldoc.LegalVersion, error) {
	docType, err := normalizeDocType(req.DocType)
	if err != nil {
		return nil, err
	}
	versions, err := s.versionDAO.ListVersions(req.OrganizationId, docType)
	if err != nil {
		return nil, err
	}
	out := make([]*legaldoc.LegalVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, toLegalVersion(v, false))
	}
	return out, nil
}

// GetLegalVersion returns one exact version (admin audit / deep-link view);
// the archived snapshot content is included when present.
func (s *Service) GetLegalVersion(req *legaldoc.GetLegalVersionRequest) (*legaldoc.LegalVersion, error) {
	docType, err := normalizeDocType(req.DocType)
	if err != nil {
		return nil, err
	}
	if req.Version <= 0 {
		return nil, errno.ParamErr
	}
	v, err := s.versionDAO.GetVersionByNumber(req.OrganizationId, docType, req.Version)
	if err != nil {
		return nil, err
	}
	return toLegalVersion(v, true), nil
}

// GetPublicLegalDoc serves the version effective NOW for App login/signup
// pages, no auth required. With a matching client version it answers
// unchanged=true without the payload. include_content=false returns metadata
// only (version/url/hash) so clients can render links without the full text.
func (s *Service) GetPublicLegalDoc(req *legaldoc.GetPublicLegalDocRequest) (*legaldoc.GetPublicLegalDocResponse, error) {
	docType, err := normalizeDocType(req.DocType)
	if err != nil {
		return nil, err
	}
	v, err := s.versionDAO.GetActiveVersion(req.OrganizationId, docType, time.Now().Unix())
	if err != nil {
		if errors.Is(err, db.ErrLegalDocNotExist) {
			// 组织尚未发布：返回 200 + version=null，客户端展示占位文案
			return &legaldoc.GetPublicLegalDocResponse{
				Code:    errno.SuccessCode,
				Message: errno.SuccessMsg,
			}, nil
		}
		hlog.CtxErrorf(s.ctx, "get public legal doc %s for org %d: %v", docType, req.OrganizationId, err)
		return nil, err
	}
	if req.Version > 0 && req.Version == v.Version {
		return &legaldoc.GetPublicLegalDocResponse{
			Code:      errno.SuccessCode,
			Message:   errno.SuccessMsg,
			Unchanged: true,
		}, nil
	}
	return &legaldoc.GetPublicLegalDocResponse{
		Code:      errno.SuccessCode,
		Message:   errno.SuccessMsg,
		Version:   toLegalVersion(v, req.IncludeContent && v.HasSnapshot),
		Unchanged: false,
	}, nil
}

// currentPublisher derives the "published by" label from the admin token
// context (the JWT middleware exposes the account id; email is not in the
// context, so the label is admin#<id>).
func (s *Service) currentPublisher() string {
	if v, ok := s.c.Get(jwt.CtxKeyUserID); ok {
		if id, ok := v.(int64); ok && id > 0 {
			return fmt.Sprintf("admin#%d", id)
		}
	}
	return "admin"
}

// toLegalVersion maps a DB row to the API model. withContent controls whether
// the archived snapshot travels with the response.
func toLegalVersion(v *db.OrganizationLegalDocVersion, withContent bool) *legaldoc.LegalVersion {
	out := &legaldoc.LegalVersion{
		Version:     v.Version,
		DocType:     v.DocType,
		Url:         v.URL,
		Changelog:   v.Changelog,
		Status:      v.Status,
		EffectiveAt: v.EffectiveAt,
		PublishedBy: v.PublishedBy,
		PublishedAt: v.PublishedAt,
		ContentHash: v.ContentHash,
		HasSnapshot: v.HasSnapshot,
	}
	if withContent && v.HasSnapshot {
		out.Content = v.Content
	}
	return out
}
