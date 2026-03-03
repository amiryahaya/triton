#!/bin/bash
set -euo pipefail

# Triton License Server — VPS Setup Script
# Run as root on a fresh Ubuntu VPS
# Usage: bash setup-vps.sh

echo "=== Triton License Server VPS Setup ==="

# --- 1. Install PostgreSQL ---
echo ""
echo "[1/5] Installing PostgreSQL..."
apt-get update -qq
apt-get install -y -qq postgresql postgresql-contrib > /dev/null

systemctl enable postgresql
systemctl start postgresql

# --- 2. Create database user and database ---
echo "[2/5] Setting up database..."

# Generate a random DB password
DB_PASS=$(openssl rand -hex 16)

sudo -u postgres psql -v ON_ERROR_STOP=1 <<EOSQL
-- Create user if not exists
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'triton') THEN
        CREATE ROLE triton WITH LOGIN PASSWORD '${DB_PASS}';
    END IF;
END
\$\$;

-- Create database if not exists
SELECT 'CREATE DATABASE triton_license OWNER triton'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'triton_license')\gexec
EOSQL

echo "  Database 'triton_license' created with user 'triton'"

# --- 3. Configure PostgreSQL to accept local connections ---
echo "[3/5] Configuring PostgreSQL authentication..."

PG_VERSION=$(pg_config --version | grep -oP '\d+' | head -1)
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

# Ensure md5 auth for local TCP connections
if ! grep -q "host.*triton_license.*triton.*127.0.0.1" "$PG_HBA"; then
    echo "host    triton_license  triton          127.0.0.1/32            scram-sha-256" >> "$PG_HBA"
fi

systemctl reload postgresql

# --- 4. Create deployment directory and env file ---
echo "[4/5] Creating deployment directory..."

mkdir -p /opt/triton

if [ -f /opt/triton/.env ]; then
    echo "  /opt/triton/.env already exists — skipping (edit manually if needed)"
else
    cat > /opt/triton/.env <<EOF
TRITON_LICENSE_SERVER_DB_URL=postgres://triton:${DB_PASS}@127.0.0.1:5432/triton_license?sslmode=disable
TRITON_LICENSE_SERVER_ADMIN_KEY=REPLACE_WITH_YOUR_ADMIN_KEY
TRITON_LICENSE_SERVER_SIGNING_KEY=REPLACE_WITH_YOUR_SIGNING_KEY
TRITON_LICENSE_SERVER_LISTEN=:8081
EOF
    chmod 600 /opt/triton/.env
    echo "  Created /opt/triton/.env (edit to add your admin key and signing key)"
fi

# --- 5. Configure firewall ---
echo "[5/5] Configuring firewall..."

if command -v ufw &> /dev/null; then
    ufw allow 22/tcp   > /dev/null 2>&1  # SSH
    ufw allow 80/tcp   > /dev/null 2>&1  # HTTP (Caddy)
    ufw allow 443/tcp  > /dev/null 2>&1  # HTTPS (Caddy)
    # Note: 8081 is NOT opened — Caddy reverse proxies to it on localhost
    ufw --force enable > /dev/null 2>&1
    echo "  Firewall: SSH(22), HTTP(80), HTTPS(443) allowed"
else
    echo "  ufw not found — configure your firewall manually"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Database password: ${DB_PASS}"
echo "Database URL:      postgres://triton:${DB_PASS}@127.0.0.1:5432/triton_license?sslmode=disable"
echo ""
echo "NEXT STEPS:"
echo "  1. Edit /opt/triton/.env — set your ADMIN_KEY and SIGNING_KEY"
echo "  2. Point your domain A record to this server's IP"
echo "  3. Configure Caddy: sudo nano /etc/caddy/Caddyfile"
echo "     Add:"
echo "       license.yourdomain.com {"
echo "           reverse_proxy localhost:8081"
echo "       }"
echo "  4. Restart Caddy: sudo systemctl restart caddy"
echo "  5. Trigger deploy from GitHub Actions or run manually:"
echo "     podman pull ghcr.io/amiryahaya/triton-license-server:latest"
echo "     podman run -d --name triton-license-server --restart always \\"
echo "       --env-file /opt/triton/.env -p 127.0.0.1:8081:8081 \\"
echo "       ghcr.io/amiryahaya/triton-license-server:latest"
echo ""
echo "SAVE THIS — Database password will not be shown again: ${DB_PASS}"
