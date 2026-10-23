# ---- Nuclei binary + templates (pinned, self-contained) ----
FROM projectdiscovery/nuclei:v3.3.4 AS nuclei-base
# Clone the public template repo via git (more reliable than nuclei's CDN on
# restricted networks), pinned to a release tag.
RUN apk add --no-cache git \
 && git clone --depth 1 --branch v10.4.8 \
      https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates

# ---- Build the orchestrator ----
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /tijeri-orchestrator ./cmd/orchestrator

# ---- Runtime ----
FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata nmap python3 py3-pip busybox-extras \
 && pip3 install --no-cache-dir --break-system-packages sslyze
COPY --from=nuclei-base /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei-base /root/nuclei-templates /root/nuclei-templates
WORKDIR /app
COPY --from=builder /tijeri-orchestrator .
COPY migrations/ ./migrations/
COPY ml/ ./ml/
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=5 \
  CMD wget -qO- --no-check-certificate https://127.0.0.1:8080/health >/dev/null 2>&1 || exit 1
ENTRYPOINT ["./tijeri-orchestrator"]
