package session

import (
	handler "github.com/authboot/authboot-server/biz/handler/session"
	"github.com/authboot/authboot-server/biz/mw/jwt"
	"github.com/cloudwego/hertz/pkg/app/server"
)

func registerSecurity(r *server.Hertz) {
	group := r.Group("/api/v1/me/security", jwt.UserSessionAuth())
	group.GET("/devices", handler.MyDevices)
	group.GET("/sessions", handler.MySessions)
	group.GET("/events", handler.MyEvents)
	group.POST("/revoke", handler.RevokeMySessions)
	group.POST("/confirm", handler.ConfirmSecurityEvent)
}
