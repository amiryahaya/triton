#!/usr/bin/env bash
# =============================================================================
#  deploy-licenseserver.sh — build, push, and deploy the Triton license server
# =============================================================================
#
# Usage:
#   ./scripts/deploy-licenseserver.sh [OPTIONS]
#
# Options:
#   --version TAG     Image version tag (default: git describe, e.g. v1.2.3)
#   --registry URL    Registry prefix, e.g. docker.io/yourorg
#                     or registry.yourhost.com:5000
#                     Leave unset to build locally only (no push).
#   --push            Push to registry (required when --registry is set)
#   --export FILE     Save image to a .tar file for air-gapped transfer
#   --compose-file F  Compose file to use (default: compose.yaml in repo root)
#   --no-build        Skip build — pull the tagged image from registry instead
#   --no-deploy       Build/push only; skip the podman-compose up step
#   --env-file FILE   .env file for compose (default: .env in repo root)
#   -h, --help        Show this help
#
# Registry options:
#   Docker Hub          export REGISTRY=docker.io/yourorg
#   Self-hosted         export REGISTRY=registry.yourhost.com:5000
#   DigitalOcean        export REGISTRY=registry.digitalocean.com/yourorg
#   Air-gapped (none)   omit --registry; use --export to produce a tar file
#
# Examples:
#   # Build, push to Docker Hub, deploy
#   ./scripts/deploy-licenseserver.sh --registry docker.io/acme --push
#
#   # Build locally, export tar for air-gapped transfer, no deploy
#   ./scripts/deploy-licenseserver.sh --export /tmp/license-server.tar --no-deploy
#
#   # Deploy using an already-pushed image (no local build)
#   ./scripts/deploy-licenseserver.sh --no-build --registry docker.io/acme --version v1.2.3
#
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RESET='\033[0m'
info()  { printf "${GREEN}[deploy]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[warn]${RESET}  %s\n" "$*" >&2; }
die()   { printf "${RED}[error]${RESET} %s\n" "$*" >&2; exit 1; }
step()  { printf "\n${GREEN}===>${RESET} %s\n" "$*"; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION=""
REGISTRY="${REGISTRY:-}"
DO_PUSH=false
EXPORT_FILE=""
COMPOSE_FILE="${REPO_ROOT}/compose.yaml"
NO_BUILD=false
NO_DEPLOY=false
ENV_FILE="${REPO_ROOT}/.env"
IMAGE_NAME="triton-license-server"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    VERSION="$2";       shift 2 ;;
    --registry)   REGISTRY="$2";      shift 2 ;;
    --push)       DO_PUSH=true;        shift   ;;
    --export)     EXPORT_FILE="$2";   shift 2 ;;
    --compose-file) COMPOSE_FILE="$2"; shift 2 ;;
    --no-build)   NO_BUILD=true;       shift   ;;
    --no-deploy)  NO_DEPLOY=true;      shift   ;;
    --env-file)   ENV_FILE="$2";      shift 2 ;;
    -h|--help)
      sed -n '/^# Usage/,/^# ====/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *) die "unknown option: $1 (run with -h for help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Resolve version tag
# ---------------------------------------------------------------------------
if [[ -z "$VERSION" ]]; then
  if git -C "$REPO_ROOT" describe --tags --exact-match HEAD 2>/dev/null; then
    VERSION="$(git -C "$REPO_ROOT" describe --tags --exact-match HEAD)"
  else
    # Use short commit hash with dirty indicator for non-tagged builds
    VERSION="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo 'dev')"
    warn "not on a tagged commit — using version: ${VERSION}"
  fi
fi

# Strip leading 'v' for image tag consistency (v1.2.3 → 1.2.3)
IMAGE_TAG="${VERSION#v}"

# ---------------------------------------------------------------------------
# Resolve full image reference
# ---------------------------------------------------------------------------
if [[ -n "$REGISTRY" ]]; then
  FULL_IMAGE="${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
  LATEST_IMAGE="${REGISTRY}/${IMAGE_NAME}:latest"
else
  # Local-only: just use a plain name for podman compose
  FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"
  LATEST_IMAGE="${IMAGE_NAME}:latest"
fi

info "image:   ${FULL_IMAGE}"
info "compose: ${COMPOSE_FILE}"
[[ -f "$ENV_FILE" ]] && info "env:     ${ENV_FILE}" || warn ".env file not found at ${ENV_FILE} — compose will rely on exported environment variables"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
command -v podman         >/dev/null || die "podman not found in PATH"
command -v podman-compose >/dev/null || command -v "podman" >/dev/null || die "podman-compose not found in PATH"
[[ -f "$COMPOSE_FILE" ]]  || die "compose file not found: ${COMPOSE_FILE}"

if $DO_PUSH && [[ -z "$REGISTRY" ]]; then
  die "--push requires --registry"
fi

# ---------------------------------------------------------------------------
# Step 1: Build
# ---------------------------------------------------------------------------
if ! $NO_BUILD; then
  step "Building ${FULL_IMAGE}"
  podman build \
    --file "${REPO_ROOT}/Containerfile.licenseserver" \
    --tag "${FULL_IMAGE}" \
    --tag "${LATEST_IMAGE}" \
    --build-arg "VERSION=${VERSION}" \
    "${REPO_ROOT}"
  info "build complete"
fi

# ---------------------------------------------------------------------------
# Step 2: Export (air-gapped transfer)
# ---------------------------------------------------------------------------
if [[ -n "$EXPORT_FILE" ]]; then
  step "Exporting image to ${EXPORT_FILE}"
  podman save --output "${EXPORT_FILE}" "${FULL_IMAGE}"
  info "saved to ${EXPORT_FILE} (transfer with scp/rsync, load with: podman load -i ${EXPORT_FILE})"
fi

# ---------------------------------------------------------------------------
# Step 3: Push to registry
# ---------------------------------------------------------------------------
if $DO_PUSH; then
  step "Pushing ${FULL_IMAGE}"
  podman push "${FULL_IMAGE}"
  podman push "${LATEST_IMAGE}"
  info "pushed ${FULL_IMAGE}"
  info "pushed ${LATEST_IMAGE}"
fi

# ---------------------------------------------------------------------------
# Step 4: Deploy with podman-compose
# ---------------------------------------------------------------------------
if $NO_DEPLOY; then
  info "skipping deploy (--no-deploy)"
  exit 0
fi

step "Deploying with podman-compose"

# Export the resolved image reference so compose.yaml picks it up via
# ${TRITON_LICENSE_SERVER_IMAGE}.
export TRITON_LICENSE_SERVER_IMAGE="${FULL_IMAGE}"

COMPOSE_ARGS=(--file "${COMPOSE_FILE}" --profile license-server)
[[ -f "$ENV_FILE" ]] && COMPOSE_ARGS+=(--env-file "${ENV_FILE}")

# Pull the new image if it was pushed to a registry (not a local build).
if $DO_PUSH; then
  info "pulling latest image on target…"
  podman-compose "${COMPOSE_ARGS[@]}" pull license-server 2>/dev/null || true
fi

podman-compose "${COMPOSE_ARGS[@]}" up --detach --remove-orphans

# ---------------------------------------------------------------------------
# Step 5: Health check
# ---------------------------------------------------------------------------
step "Waiting for health check"

LISTEN_PORT="${TRITON_LICENSE_SERVER_LISTEN:-:8081}"
HOST_PORT="${LISTEN_PORT#:}"   # strip leading colon
HEALTH_URL="http://localhost:${HOST_PORT}/api/v1/health"
MAX_RETRIES=20
RETRY_SLEEP=3

for i in $(seq 1 $MAX_RETRIES); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    info "license server is healthy at ${HEALTH_URL}"
    break
  fi
  if [[ $i -eq $MAX_RETRIES ]]; then
    warn "health check timed out after $((MAX_RETRIES * RETRY_SLEEP))s — check container logs:"
    warn "  podman logs triton-license-server"
    exit 1
  fi
  printf "  waiting (%d/%d)…\r" "$i" "$MAX_RETRIES"
  sleep "$RETRY_SLEEP"
done

step "Deploy complete"
info "Admin UI: http://localhost:${HOST_PORT}/ui/"
info "API:      http://localhost:${HOST_PORT}/api/v1/"
info ""
info "Useful commands:"
info "  podman logs -f triton-license-server"
info "  podman-compose --file ${COMPOSE_FILE} --profile license-server down"
