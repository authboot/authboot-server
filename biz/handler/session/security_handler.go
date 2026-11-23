package session

import (
	"context"

	model "github.com/authboot/authboot-server/biz/model/security"
	service "github.com/authboot/authboot-server/biz/service/session"
	"github.com/authboot/authboot-server/pkg/utils"
	"github.com/cloudwego/hertz/pkg/app"
)

func securityReply(c *app.RequestContext, response interface{}, err error) {
	if err != nil {
		base := utils.BuildBaseResp(err)
		c.JSON(200, map[string]interface{}{"code": base.StatusCode, "message": base.StatusMsg})
		return
	}
	c.JSON(200, response)
}
func MyDevices(ctx context.Context, c *app.RequestContext) {
	var req model.PageRequest
	if err := c.BindAndValidate(&req); err != nil {
		securityReply(c, nil, err)
		return
	}
	out, err := service.NewSessionService(ctx, c).MyDevices(&req)
	securityReply(c, out, err)
}
func MySessions(ctx context.Context, c *app.RequestContext) {
	var req model.PageRequest
	if err := c.BindAndValidate(&req); err != nil {
		securityReply(c, nil, err)
		return
	}
	out, err := service.NewSessionService(ctx, c).MySessions(&req)
	securityReply(c, out, err)
}
func MyEvents(ctx context.Context, c *app.RequestContext) {
	var req model.PageRequest
	if err := c.BindAndValidate(&req); err != nil {
		securityReply(c, nil, err)
		return
	}
	out, err := service.NewSessionService(ctx, c).MyEvents(&req)
	securityReply(c, out, err)
}
func RevokeMySessions(ctx context.Context, c *app.RequestContext) {
	var req model.RevokeRequest
	if err := c.BindAndValidate(&req); err != nil {
		securityReply(c, nil, err)
		return
	}
	out, err := service.NewSessionService(ctx, c).RevokeMySessions(&req)
	securityReply(c, out, err)
}
func ConfirmSecurityEvent(ctx context.Context, c *app.RequestContext) {
	var req model.ConfirmRequest
	if err := c.BindAndValidate(&req); err != nil {
		securityReply(c, nil, err)
		return
	}
	out, err := service.NewSessionService(ctx, c).ConfirmSecurityEvent(&req)
	securityReply(c, out, err)
}
