// Package emailtemplate implements per-organization overrides of the system
// email templates. The catalog is the registry in biz/mw/email; overrides are
// compiled and dry-run before they are written so sending never hits a broken
// template.
package emailtemplate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"

	"github.com/authboot/authboot-server/biz/dal/db"
	model "github.com/authboot/authboot-server/biz/model/emailtemplate"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/authboot/authboot-server/pkg/errno"
)

const testSendTimeout = 15 * time.Second

// EmailTemplateService manages template overrides.
type EmailTemplateService struct {
	ctx context.Context
	c   *app.RequestContext

	dao *db.EmailTemplateDAO
}

// NewEmailTemplateService creates a template service.
func NewEmailTemplateService(ctx context.Context, c *app.RequestContext) *EmailTemplateService {
	return &EmailTemplateService{ctx: ctx, c: c, dao: db.NewEmailTemplateDAO(db.DB)}
}

// ListTemplateCatalog returns every system email with its variables and
// built-in default wording.
func (s *EmailTemplateService) ListTemplateCatalog(_ *model.ListTemplateCatalogRequest) (*model.ListTemplateCatalogResponse, error) {
	catalog := email.TemplateCatalog()
	out := make([]*model.TemplateDescriptor, 0, len(catalog))
	for _, d := range catalog {
		out = append(out, toDescriptor(d))
	}
	return &model.ListTemplateCatalogResponse{
		Code:      errno.SuccessCode,
		Message:   errno.SuccessMsg,
		Templates: out,
	}, nil
}

// ListTemplateOverrides returns the overrides an organization has saved.
func (s *EmailTemplateService) ListTemplateOverrides(req *model.ListTemplateOverridesRequest) (*model.ListTemplateOverridesResponse, error) {
	if req.OrganizationId == 0 {
		return nil, errno.ParamErr
	}
	rows, err := s.dao.List(req.OrganizationId)
	if err != nil {
		return nil, err
	}
	out := make([]*model.TemplateOverride, 0, len(rows))
	for _, row := range rows {
		out = append(out, toOverride(row))
	}
	return &model.ListTemplateOverridesResponse{
		Code:      errno.SuccessCode,
		Message:   errno.SuccessMsg,
		Overrides: out,
	}, nil
}

// SetTemplateOverride compiles and dry-runs the submitted template, then
// saves it and drops the cached copy. Nothing is written on a compile error.
func (s *EmailTemplateService) SetTemplateOverride(req *model.SetTemplateOverrideRequest) (*model.SetTemplateOverrideResponse, error) {
	d, err := s.descriptor(req.OrganizationId, req.TemplateId)
	if err != nil {
		return nil, err
	}
	if _, err := d.Compile(req.Subject, req.Body); err != nil {
		return nil, err
	}
	row := &db.EmailTemplate{
		OrganizationID: req.OrganizationId,
		TemplateID:     d.ID,
		Subject:        strings.TrimSpace(req.Subject),
		Body:           req.Body,
	}
	if err := s.dao.Upsert(row); err != nil {
		return nil, err
	}
	email.InvalidateTemplate(req.OrganizationId, d.ID)

	saved, err := s.dao.Query(req.OrganizationId, d.ID)
	if err != nil {
		return nil, err
	}
	return &model.SetTemplateOverrideResponse{
		Code:     errno.SuccessCode,
		Message:  errno.SuccessMsg,
		Override: toOverride(saved),
	}, nil
}

// ResetTemplateOverride deletes the override so the default applies again.
func (s *EmailTemplateService) ResetTemplateOverride(req *model.ResetTemplateOverrideRequest) (*model.ResetTemplateOverrideResponse, error) {
	d, err := s.descriptor(req.OrganizationId, req.TemplateId)
	if err != nil {
		return nil, err
	}
	if err := s.dao.Delete(req.OrganizationId, d.ID); err != nil {
		return nil, err
	}
	email.InvalidateTemplate(req.OrganizationId, d.ID)
	return &model.ResetTemplateOverrideResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// PreviewTemplate renders the submitted (or, when empty, the currently
// effective) template with the sample variables. Nothing is written.
func (s *EmailTemplateService) PreviewTemplate(req *model.PreviewTemplateRequest) (*model.PreviewTemplateResponse, error) {
	d, err := s.descriptor(req.OrganizationId, req.TemplateId)
	if err != nil {
		return nil, err
	}
	subject, html, err := s.render(req.OrganizationId, d, req.Subject, req.Body)
	if err != nil {
		return nil, err
	}
	return &model.PreviewTemplateResponse{
		Code:    errno.SuccessCode,
		Message: errno.SuccessMsg,
		Subject: subject,
		Html:    html,
	}, nil
}

// SendTestTemplate renders like PreviewTemplate and delivers the result
// through the organization's email provider.
func (s *EmailTemplateService) SendTestTemplate(req *model.SendTestTemplateRequest) (*model.SendTestTemplateResponse, error) {
	d, err := s.descriptor(req.OrganizationId, req.TemplateId)
	if err != nil {
		return nil, err
	}
	subject, html, err := s.render(req.OrganizationId, d, req.Subject, req.Body)
	if err != nil {
		return nil, err
	}
	recipient, err := s.recipient(req.Recipient)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(s.ctx, testSendTimeout)
	defer cancel()
	if err := email.SendFor(ctx, req.OrganizationId, &email.Message{
		To:      []string{recipient},
		Subject: "[Test] " + subject,
		HTML:    html,
	}); err != nil {
		return nil, fmt.Errorf("test email failed: %w", err)
	}
	return &model.SendTestTemplateResponse{Code: errno.SuccessCode, Message: errno.SuccessMsg}, nil
}

// descriptor validates the common path params and resolves the template.
func (s *EmailTemplateService) descriptor(orgID int64, templateID string) (*email.TemplateDescriptor, error) {
	if orgID == 0 || strings.TrimSpace(templateID) == "" {
		return nil, errno.ParamErr
	}
	d, ok := email.LookupTemplate(templateID)
	if !ok {
		return nil, fmt.Errorf("unknown template %q", templateID)
	}
	return d, nil
}

// render compiles the submitted subject/body when given, otherwise uses the
// organization's effective template, and executes it with the sample data.
func (s *EmailTemplateService) render(orgID int64, d *email.TemplateDescriptor, subject, body string) (string, string, error) {
	if strings.TrimSpace(subject) == "" && strings.TrimSpace(body) == "" {
		return email.RenderFor(s.ctx, orgID, d.ID, d.SampleData())
	}
	c, err := d.Compile(subject, body)
	if err != nil {
		return "", "", err
	}
	return c.Execute(d.SampleData())
}

// recipient resolves the test address: explicit value, else the email of the
// admin making the request.
func (s *EmailTemplateService) recipient(explicit string) (string, error) {
	if r := strings.TrimSpace(explicit); r != "" {
		return r, nil
	}
	adminID, _ := s.c.Get(jwt.CtxKeyUserID)
	id, _ := adminID.(int64)
	if id == 0 {
		return "", fmt.Errorf("recipient is required")
	}
	admin, err := db.QueryAdminUserByID(id)
	if err != nil || strings.TrimSpace(admin.Email) == "" {
		return "", fmt.Errorf("recipient is required: current admin has no email")
	}
	return admin.Email, nil
}

func toDescriptor(d *email.TemplateDescriptor) *model.TemplateDescriptor {
	vars := make([]*model.TemplateVariable, 0, len(d.Variables))
	for _, v := range d.Variables {
		vars = append(vars, &model.TemplateVariable{
			Name:        v.Name,
			Description: v.Description,
			Sample:      v.Sample,
			Required:    v.Required,
		})
	}
	return &model.TemplateDescriptor{
		TemplateId:     d.ID,
		Name:           d.Name,
		Trigger:        d.Trigger,
		Variables:      vars,
		DefaultSubject: d.DefaultSubject,
		DefaultBody:    d.DefaultBody(),
	}
}

func toOverride(row *db.EmailTemplate) *model.TemplateOverride {
	return &model.TemplateOverride{
		OrganizationId: row.OrganizationID,
		TemplateId:     row.TemplateID,
		Subject:        row.Subject,
		Body:           row.Body,
		CreatedAt:      row.CreatedAt.Unix(),
		UpdatedAt:      row.UpdatedAt.Unix(),
	}
}
