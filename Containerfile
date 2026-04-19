# Stage 1: Build Report Portal web assets (Vite)
FROM docker.io/library/node:22-alpine AS web
WORKDIR /app
RUN corepack enable pnpm
COPY web/ /app/web/
WORKDIR /app/web
RUN pnpm install --frozen-lockfile && pnpm --filter report-portal build

# Stage 2: Build static Go binary
FROM docker.io/library/golang:1.26 AS builder

ARG VERSION=dev
ARG PUBLIC_KEY_HEX=""

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Copy the Vite-built portal into the Go embed target so //go:embed sees it.
COPY --from=web /app/pkg/server/ui/dist /src/pkg/server/ui/dist

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/amiryahaya/triton/internal/version.Version=${VERSION} -X github.com/amiryahaya/triton/internal/license.publicKeyHex=${PUBLIC_KEY_HEX}" \
    -o /triton main.go

# Stage 3: Minimal production image
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
