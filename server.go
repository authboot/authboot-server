package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/accesslog"
	"github.com/authboot/authboot-server/biz/mw/redis"
	"github.com/authboot/authboot-server/biz/mw/tracing"
	"github.com/authboot/authboot-server/pkg/securitymetrics"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/middlewares/server/recovery"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/hertz-contrib/reverseproxy"
	"github.com/hertz-contrib/sessions"
	"github.com/hertz-contrib/sessions/cookie"
)

func newServer() (*server.Hertz, error) {
	proxy, err := reverseproxy.NewSingleHostReverseProxy("http://localhost:18001")
	if err != nil {
		return nil, fmt.Errorf("initialize minio reverse proxy: %w", err)
	}
	// Default 自带一层最外层的 recovery，只为下面前三个中间件自身出错兜底。
	h := server.Default(
		server.WithStreamBody(true),
		server.WithHostPorts("0.0.0.0:8888"),
	)
	store := cookie.NewStore([]byte("secret"))
	// 顺序不能调换：先确定请求 ID 和 trace ID，访问日志把它们绑进 ctx 供后续所有日志使用；
	// recovery 放在访问日志里面，业务 panic 先被转成 500，再作为一条访问日志记录下来。
	// 审计记录读取的是同一个请求 ID。
	h.Use(
		accesslog.RequestID(),
		tracing.TraceContext(),
		accesslog.New(accesslog.Skip("/ping", "/internal/metrics", "/internal/ready")),
		recovery.Recovery(),
		sessions.New("session", store),
	)
	h.GET("/src/*name", func(c context.Context, ctx *app.RequestContext) {
		ctx.URI().SetPath(ctx.Param("name"))
		hlog.CtxInfof(c, "%s", ctx.Request.URI().Path())
		proxy.ServeHTTP(c, ctx)
	})
	register(h)
	h.GET("/internal/metrics", securitymetrics.Handler(os.Getenv("SECURITY_METRICS_TOKEN")))
	h.GET("/internal/ready", func(ctx context.Context, c *app.RequestContext) {
		c.Header("Cache-Control", "no-store")
		if !securitymetrics.Authorized(c, os.Getenv("SECURITY_METRICS_TOKEN")) {
			c.AbortWithStatus(401)
			return
		}
		if db.DB == nil {
			c.AbortWithStatus(503)
			return
		}
		sqlDB, err := db.DB.DB()
		if err != nil {
			c.AbortWithStatus(503)
			return
		}
		check, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		if sqlDB.PingContext(check) != nil || (redis.SessionStore{}).Healthy() != nil {
			c.AbortWithStatus(503)
			return
		}
		c.JSON(200, map[string]string{"status": "ready"})
	})
	return h, nil
}
