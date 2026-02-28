# syntax=docker/dockerfile:1

# ─── Stage 1: Build the Go proxy ─────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Copy module files first for layer-cache efficiency.
COPY proxy/go.mod proxy/go.sum ./

# Download dependencies.
RUN go mod download

# Copy source and build a fully static binary.
COPY proxy/ ./
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -trimpath \
    -o /app/proxy \
    .

# ─── Stage 2: Minimal runtime image ──────────────────────────────────────────
FROM alpine:3.20

# tor             — the Tor anonymity network daemon
# ca-certificates — needed for TLS to upstream HTTPS endpoints
# tini            — minimal init: reaps zombies, forwards signals correctly
RUN apk add --no-cache \
    tor \
    ca-certificates \
    tini

# Copy the compiled proxy binary.
COPY --from=builder /app/proxy /app/proxy

# Copy the startup script.
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Runtime manifest directory (written by entrypoint.sh, read by proxy).
RUN mkdir -p /run/tor-proxy

# ─── Configuration ────────────────────────────────────────────────────────────
# Environment variable defaults (all overridable at runtime).
ENV MANIFEST_PATH=/run/tor-proxy/manifest.json \
    PROXY_PORT=8080 \
    WEB_UI_PORT=8088 \
    LEASE_TIMEOUT=30s \
    DIAL_TIMEOUT=120s \
    LOG_LEVEL=info \
    TOR_INSTANCES=10 \
    TOR_BASE_SOCKS_PORT=9050 \
    TOR_BASE_CTRL_PORT=10050 \
    TOR_BOOTSTRAP_TIMEOUT=120

# Proxy port
EXPOSE 8080
# Web UI port
EXPOSE 8088

# tini is PID 1: handles signal forwarding and zombie reaping for the
# entrypoint.sh → proxy process chain.
ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
