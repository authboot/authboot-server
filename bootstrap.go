package main

import (
	"context"
	"errors"

	"github.com/authboot/authboot-server/biz/dal"
	"github.com/authboot/authboot-server/biz/dal/db"
	"github.com/authboot/authboot-server/biz/mw/audit"
	"github.com/authboot/authboot-server/biz/mw/captcha"
	"github.com/authboot/authboot-server/biz/mw/email"
	"github.com/authboot/authboot-server/biz/mw/minio"
	"github.com/authboot/authboot-server/biz/mw/oauth"
	"github.com/authboot/authboot-server/biz/securityops"
	"github.com/authboot/authboot-server/pkg/clientip"
	"github.com/authboot/authboot-server/pkg/geoip"
	"github.com/authboot/authboot-server/pkg/logger"
)

// Init 保留依赖初始化顺序，环境变量仍由原有部署方式提供。
func Init() {
	geoip.Init()
	clientip.Init()
	dal.Init()
	captcha.Init()
	minio.Init()
	email.Init()
	// 组织 OAuth 凭据按需从 oauth_configs 表加载。
	oauth.Init(oauth.NewDBStore())
}

func run() (err error) {
	// 最先接管日志：hlog 与标准库 log 都汇入同一个 logger，后续依赖初始化的输出不会丢。
	closeLogging, err := logger.Init(logger.ConfigFromEnv())
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeLogging()) }()

	defer geoip.Close()
	Init()
	audit.Init(4096)
	audit.Start()
	// 先排空审计队列，再关闭 geoip 和日志。
	defer audit.Stop()
	workerConfig, err := securityops.FromEnv()
	if err != nil {
		return err
	}
	worker := &securityops.Worker{DB: db.DB, Config: workerConfig}
	stopWorker := worker.Start(context.Background())
	defer stopWorker()

	h, err := newServer()
	if err != nil {
		return err
	}
	h.Spin()
	return nil
}
