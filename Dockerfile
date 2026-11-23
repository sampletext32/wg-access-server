### Build stage for the website frontend
FROM --platform=$BUILDPLATFORM node:26.13.0-bookworm AS website
WORKDIR /code
COPY ./website/package.json ./
COPY ./website/package-lock.json ./
RUN npm ci --no-audit --prefer-offline
COPY ./website/ ./
RUN npm run build

### Build stage for the website backend server
FROM golang:1.27.3-alpine AS server
RUN apk add --no-cache gcc musl-dev
WORKDIR /code
ENV CGO_ENABLED=1
ARG VERSION=development
ARG COMMIT="-"
COPY ./go.mod ./
COPY ./go.sum ./
RUN go mod download
RUN go mod verify
COPY ./proto/proto/ ./proto/proto/
COPY ./main.go ./main.go
COPY ./cmd/ ./cmd/
COPY ./internal/ ./internal/
COPY ./buildinfo/ ./buildinfo/
RUN echo "Using: Version: ${VERSION}, Commit: ${COMMIT}"
RUN go generate buildinfo/buildinfo.go
RUN go build -o wg-access-server

### Xray-core, the second dataplane
#
# Fetched from the release rather than from an image: the binary is the whole
# artifact, and a checksum from the release's own .dgst file makes the build
# fail if the URL ever serves something else. A new version means a new
# checksum - take both from the release page, never one without the other.
FROM alpine:3.24.3 AS xray
ARG XRAY_VERSION=26.11.9
ARG XRAY_SHA256=b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82
RUN apk add --no-cache curl unzip && \
    curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" && \
    echo "${XRAY_SHA256}  /tmp/xray.zip" | sha256sum -c - && \
    unzip -q -j /tmp/xray.zip xray -d /usr/local/bin && \
    chmod 0755 /usr/local/bin/xray

### Server
FROM alpine:3.24.3
RUN apk add --no-cache ca-certificates iptables ip6tables nftables wireguard-tools curl openssl
ENV WG_CONFIG="/config.yaml"
# An empty config file at the path above, so that the server starts on its
# defaults and the environment variables when no config file is mounted over
# it. Without the file, reading the configured path fails and the server
# refuses to start - which is what an operator wants for a path they typed
# themselves, but this path is the image's own.
RUN touch /config.yaml
ENV WG_STORAGE="sqlite3:///data/db.sqlite3"
# Keep the generated self-signed certificate on the data volume, otherwise a
# recreated container serves a new certificate and every browser warns again
ENV WG_HTTPS_CERT_FILE="/data/wg-access-server.crt"
ENV WG_HTTPS_KEY_FILE="/data/wg-access-server.key"
COPY --from=server /code/wg-access-server /usr/local/bin/wg-access-server
COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY --from=website /code/build /website/build
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || curl -fk https://localhost:8443/health || exit 1
CMD ["wg-access-server", "serve"]
