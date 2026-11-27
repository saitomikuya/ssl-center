# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM node:22-alpine AS web-builder
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS go-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web-builder /src/internal/web/dist ./internal/web/dist
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/ssl-center ./cmd/server

FROM alpine:3.21
LABEL org.opencontainers.image.title="ssl-center" \
      org.opencontainers.image.description="Lightweight ACME SSL certificate issuer, push deployment engine, and Caddy Docker operations console" \
      org.opencontainers.image.source="https://github.com/saitomikuya/ssl-center" \
      org.opencontainers.image.licenses="MIT"
RUN apk add --no-cache ca-certificates tzdata docker-cli || \
    (sleep 2 && apk add --no-cache ca-certificates tzdata docker-cli)
ENV DATA_DIR=/data \
    LISTEN_ADDR=:8080 \
    TZ=Asia/Shanghai
WORKDIR /app
COPY --from=go-builder /out/ssl-center /usr/local/bin/ssl-center
RUN mkdir -p /data/certs /data/tmp
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1 || exit 1
ENTRYPOINT ["/usr/local/bin/ssl-center"]
