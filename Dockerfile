# ---------- 构建阶段 ----------
FROM golang:1.26-alpine AS builder

# 内网代理优先，公网回退，加速依赖下载
ENV GOPROXY=https://goproxy.baidu-int.com,https://goproxy.cn,direct
WORKDIR /app

# 先拷贝依赖清单，充分利用 Docker 层缓存
COPY go.mod go.sum ./
RUN go mod download

# 拷贝源码，编译无 CGO 依赖的静态二进制
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o output/bin/hertz_service .

# ---------- 运行阶段 ----------
FROM alpine:3.20

# 时区 + CA 证书（HTTPS 出网，如 Resend 邮件，需要）
RUN apk add --no-cache ca-certificates tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

# 非 root 用户运行；预建日志目录（main.go 会写 ./hlog/logs）
RUN adduser -D -u 10001 appuser && mkdir -p /app/hlog/logs && chown -R appuser /app/hlog
WORKDIR /app
COPY --from=builder /app/output/bin/hertz_service ./bin/hertz_service

USER appuser
EXPOSE 8888
ENTRYPOINT ["./bin/hertz_service"]
