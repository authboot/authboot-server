// Package messageprovider implements per-organization message delivery
// provider configuration (email now, sms later). The catalog is the registry
// in biz/mw/email; saving a config validates it with a real test send before
// anything is written.
package messageprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"gorm.io/gorm"

	"github.com/authboot/authboot-server/biz/dal/db"
	model "github.com/authboot/authboot-server/biz/model/messageprovider"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/pkg/errno"
)

// validateTimeout bounds the test send performed by SetProviderConfig.
const validateTimeout = 15 * time.Second

// MessageProviderService manages provider configs.
type MessageProviderService struct {
	ctx context.Context
	c   *app.RequestContext

	configDAO *db.MessageProviderConfigDAO
}

// NewMessageProviderService creates a provider configuration service.
func NewMessageProviderService(ctx context.Context, c *app.RequestContext) *MessageProviderService {
	return &MessageProviderService{
		ctx:       ctx,
		c:         c,
		configDAO: db.NewMessageProviderConfigDAO(db.DB),
	}
}

// ListProviderCatalog returns the registered providers, optionally filtered
// by channel. Only the email channel is registered today.
func (s *MessageProviderService) ListProviderCatalog(req *model.ListProviderCatalogRequest) (*model.ListProviderCatalogResponse, error) {
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	out := make([]*model.ProviderDescriptor, 0)
	if channel == "" || channel == email.Channel {
		for _, d := range email.Catalog() {
			out = append(out, toDescriptor(email.Channel, d, d.ID == email.DefaultProviderID()))
		}
	}
	return &model.ListProviderCatalogResponse{
		Code:      errno.SuccessCode,
		Message:   errno.SuccessMsg,
		Providers: out,
	}, nil
}

// ListProviderConfigs returns an organization's saved configs, masked.
func (s *MessageProviderService) ListProviderConfigs(req *model.ListProviderConfigsRequest) (*model.ListProviderConfigsResponse, error) {
	if req.OrganizationId == 0 {
		return nil, errno.ParamErr
	}
	rows, err := s.configDAO.List(req.OrganizationId, strings.ToLower(strings.TrimSpace(req.Channel)))
	if err != nil {
		return nil, err
	}
	views := make([]*model.ProviderConfig, 0, len(rows))
	for _, row := range rows {
		view, err := toProviderConfig(row)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return &model.ListProviderConfigsResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Configs: views,
		Total:   int64(len(views)),
	}, nil
}

// SetProviderConfig validates then saves: secret fields left blank are filled
// from the stored config, the Sender is built and a test message is delivered;
// only on success is the config encrypted and upserted. A channel's first
// provider becomes the primary; later ones are appended as fallbacks and can
// be reordered with SetProviderPriority. Nothing is written when validation
// fails.
func (s *MessageProviderService) SetProviderConfig(req *model.SetProviderConfigRequest) (*model.SetProviderConfigResponse, error) {
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	providerID := strings.ToLower(strings.TrimSpace(req.Provider))
	if req.OrganizationId == 0 || channel == "" || providerID == "" {
		return nil, errno.ParamErr
	}
	if channel != email.Channel {
		return nil, fmt.Errorf("unsupported channel %q", channel)
	}
	desc, ok := email.Lookup(providerID)
	if !ok {
		return nil, fmt.Errorf("unsupported provider %q", providerID)
	}

	settings := make(map[string]string, len(req.Settings))
	for k, v := range req.Settings {
		settings[k] = v
	}
	if err := s.fillSecretsFromStored(req.OrganizationId, channel, providerID, desc, settings); err != nil {
		return nil, err
	}
	if err := desc.Validate(settings); err != nil {
		return nil, err
	}
	if desc.TenantCheck != nil {
		if err := desc.TenantCheck(settings); err != nil {
			return nil, err
		}
	}
	sender, err := desc.Build(settings)
	if err != nil {
		return nil, err
	}

	recipient, err := s.testRecipient(req.TestRecipient)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(s.ctx, validateTimeout)
	defer cancel()
	if err := email.SendWith(ctx, sender, testMessage(recipient, desc.Name)); err != nil {
		return nil, fmt.Errorf("provider validation failed: %w", err)
	}

	plain, err := json.Marshal(settings)
	if err != nil {
		return nil, err
	}
	sealed, err := email.Encrypt(plain)
	if err != nil {
		return nil, err
	}
	cfg := &db.MessageProviderConfig{
		OrganizationID: req.OrganizationId,
		Channel:        channel,
		Provider:       providerID,
		Config:         sealed,
		VerifiedAt:     time.Now().Unix(),
	}
	if err := s.configDAO.Upsert(cfg); err != nil {
		return nil, err
	}
	email.Invalidate(req.OrganizationId)

	saved, err := s.configDAO.QueryAny(req.OrganizationId, channel, providerID)
	if err != nil {
		return nil, err
	}
	view, err := toProviderConfig(saved)
	if err != nil {
		return nil, err
	}
	return &model.SetProviderConfigResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Config:  view,
	}, nil
}

// SetProviderPriority sets the send order of a channel: primary first, then
// fallbacks in the given order. Providers must already be saved (validated).
// An empty primary with no fallbacks takes every provider out of rotation so
// the channel falls back to the platform default.
func (s *MessageProviderService) SetProviderPriority(req *model.SetProviderPriorityRequest) (*model.SetProviderPriorityResponse, error) {
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	primary := strings.ToLower(strings.TrimSpace(req.Primary))
	if req.OrganizationId == 0 || channel == "" {
		return nil, errno.ParamErr
	}
	if primary == "" && len(req.Fallbacks) > 0 {
		return nil, fmt.Errorf("fallbacks require a primary provider")
	}
	// Empty order: the channel stops using custom providers (all priority 0).
	order := []string{}
	seen := map[string]bool{}
	if primary != "" {
		order = append(order, primary)
		seen[primary] = true
	}
	for _, fb := range req.Fallbacks {
		fb = strings.ToLower(strings.TrimSpace(fb))
		if fb == "" || seen[fb] {
			continue
		}
		seen[fb] = true
		order = append(order, fb)
	}
	if err := s.configDAO.SetPriorities(req.OrganizationId, channel, order); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("provider in order is not configured for channel %q", channel)
		}
		return nil, err
	}
	email.Invalidate(req.OrganizationId)

	rows, err := s.configDAO.List(req.OrganizationId, channel)
	if err != nil {
		return nil, err
	}
	views := make([]*model.ProviderConfig, 0, len(rows))
	for _, row := range rows {
		view, err := toProviderConfig(row)
		if err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return &model.SetProviderPriorityResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Configs: views,
	}, nil
}

// DeleteProviderConfig removes a config and invalidates the cached sender.
func (s *MessageProviderService) DeleteProviderConfig(req *model.DeleteProviderConfigRequest) (*model.DeleteProviderConfigResponse, error) {
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	providerID := strings.ToLower(strings.TrimSpace(req.Provider))
	if req.OrganizationId == 0 || channel == "" || providerID == "" {
		return nil, errno.ParamErr
	}
	if err := s.configDAO.Delete(req.OrganizationId, channel, providerID); err != nil {
		return nil, err
	}
	email.Invalidate(req.OrganizationId)
	return &model.DeleteProviderConfigResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// fillSecretsFromStored copies secret fields the request left blank from the
// previously saved config, so an admin can edit non-secret settings without
// re-entering credentials. No stored config is not an error.
func (s *MessageProviderService) fillSecretsFromStored(orgID int64, channel, providerID string, desc *email.Descriptor, settings map[string]string) error {
	needs := false
	for _, f := range desc.Fields {
		if f.Secret && strings.TrimSpace(settings[f.Name]) == "" {
			needs = true
			break
		}
	}
	if !needs {
		return nil
	}
	row, err := s.configDAO.QueryAny(orgID, channel, providerID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	stored, err := decodeStored(row)
	if err != nil {
		return err
	}
	for _, f := range desc.Fields {
		if f.Secret && strings.TrimSpace(settings[f.Name]) == "" {
			settings[f.Name] = stored[f.Name]
		}
	}
	return nil
}

// testRecipient resolves where the validation mail goes: the explicit request
// value, else the email of the admin making the request.
func (s *MessageProviderService) testRecipient(explicit string) (string, error) {
	if r := strings.TrimSpace(explicit); r != "" {
		return r, nil
	}
	adminID, _ := s.c.Get(jwt.CtxKeyUserID)
	id, _ := adminID.(int64)
	if id == 0 {
		return "", fmt.Errorf("test_recipient is required")
	}
	admin, err := db.QueryAdminUserByID(id)
	if err != nil || strings.TrimSpace(admin.Email) == "" {
		return "", fmt.Errorf("test_recipient is required: current admin has no email")
	}
	return admin.Email, nil
}

func testMessage(to, providerName string) *email.Message {
	return &email.Message{
		To:      []string{to},
		Subject: fmt.Sprintf("[Authboot] %s 邮件服务配置验证", providerName),
		Text:    fmt.Sprintf("这是一封测试邮件，用于验证 %s 邮件服务配置。收到此邮件表示配置可用。", providerName),
	}
}

func toDescriptor(channel string, d *email.Descriptor, platformDefault bool) *model.ProviderDescriptor {
	fields := make([]*model.ProviderField, 0, len(d.Fields))
	for _, f := range d.Fields {
		fields = append(fields, &model.ProviderField{
			Name:        f.Name,
			Label:       f.Label,
			Secret:      f.Secret,
			Required:    f.Required,
			Placeholder: f.Placeholder,
			Type:        f.Type,
		})
	}
	return &model.ProviderDescriptor{
		Channel:         channel,
		Provider:        d.ID,
		Name:            d.Name,
		Description:     d.Description,
		Fields:          fields,
		PlatformDefault: platformDefault,
	}
}

// decodeStored decrypts a row into its plaintext settings.
func decodeStored(row *db.MessageProviderConfig) (map[string]string, error) {
	plain, err := email.Decrypt(row.Config)
	if err != nil {
		return nil, err
	}
	var settings map[string]string
	if err := json.Unmarshal(plain, &settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// toProviderConfig renders a row for the API, masking fields the descriptor
// declares as secret.
func toProviderConfig(row *db.MessageProviderConfig) (*model.ProviderConfig, error) {
	settings, err := decodeStored(row)
	if err != nil {
		return nil, err
	}
	if desc, ok := email.Lookup(row.Provider); ok && row.Channel == email.Channel {
		for _, f := range desc.Fields {
			if f.Secret && settings[f.Name] != "" {
				if f.Name == "api_key" {
					settings[f.Name] = apiKeyPreview(settings[f.Name])
				} else {
					settings[f.Name] = maskSecret(settings[f.Name])
				}
			}
		}
	}
	return &model.ProviderConfig{
		OrganizationId: row.OrganizationID,
		Channel:        row.Channel,
		Provider:       row.Provider,
		Settings:       settings,
		Enabled:        row.Enabled == 1,
		Priority:       row.Priority,
		VerifiedAt:     row.VerifiedAt,
		CreatedAt:      row.CreatedAt.Unix(),
		UpdatedAt:      row.UpdatedAt.Unix(),
	}, nil
}

// apiKeyPreview shows a recognizable prefix and hides short keys completely.
func apiKeyPreview(key string) string {
	r := []rune(key)
	if len(r) <= 6 {
		return "****"
	}
	return string(r[:6]) + "****"
}

// maskSecret keeps a 2-character hint so operators can tell which credential
// is configured without exposing it.
func maskSecret(v string) string {
	r := []rune(v)
	if len(r) <= 2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-2)
}
