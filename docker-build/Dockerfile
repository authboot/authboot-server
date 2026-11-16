# syntax=docker/dockerfile:1

# ---- 构建阶段：编译纯静态二进制 ----
FROM golang:1.26-alpine AS build

WORKDIR /go/src
# 国内环境走 goproxy.cn 加速模块下载；CGO 关闭以便在 alpine 上直接运行
ENV GO111MODULE=on \
    GOPROXY=https://goproxy.cn,direct \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# 先拷依赖清单，命中缓存后改代码无需重新下载模块
COPY go.mod go.sum ./
RUN go mod download

# 只拷构建所需源码，避免把 .git / hlog / 本地产物打进上下文
COPY biz/ ./biz/
COPY pkg/ ./pkg/
COPY idl/ ./idl/
COPY *.go ./

RUN go build -trimpath -ldflags="-s -w" -o /out/hertz_service .

# ---- 运行阶段：只保留二进制和运行期配置 ----
FROM alpine:3.19

# ca-certificates 供 HTTPS 外呼（Resend 邮件、OAuth），tzdata 供 DSN 中 loc=Local 解析时区
RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
ENV TZ=Asia/Shanghai

COPY --from=build /out/hertz_service /app/bin/hertz_service
# 运行期按相对路径读取 casbin 模型：pkg/configs/casbin/model.conf
COPY pkg/configs /app/pkg/configs

# 应用监听 0.0.0.0:8888
EXPOSE 8888

ENTRYPOINT ["/app/bin/hertz_service"]
