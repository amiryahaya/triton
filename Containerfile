# Stage 1: Build static binary
FROM docker.io/library/golang:1.25 AS builder

ARG VERSION=dev
ARG PUBLIC_KEY_HEX=""

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION} -X github.com/amiryahaya/triton/internal/license.publicKeyHex=${PUBLIC_KEY_HEX}" \
    -o /triton main.go

# Stage 2: Minimal production image
FROM scratch

ENV HOME=/tmp
# scratch has no filesystem — create /tmp for temp file operations (e.g. Excel export)
COPY --from=builder /tmp /tmp

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /triton /triton

EXPOSE 8080

ENTRYPOINT ["/triton"]
CMD ["server"]
