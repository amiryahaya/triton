# Ubuntu Production Deployment Guide

Step-by-step guide for deploying the full Triton stack on an Ubuntu server with Nginx reverse proxy and Podman containers. Target: single Ubuntu VM serving the scan server, license server, and PostgreSQL.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Install Podman](#3-install-podman)
4. [Install Nginx](#4-install-nginx)
5. [Install PostgreSQL 18](#5-install-postgresql-18)
6. [Pull Container Images](#6-pull-container-images)
7. [Generate Secrets](#7-generate-secrets)
8. [Configure & Start Services](#8-configure--start-services)
9. [Configure Nginx Reverse Proxy](#9-configure-nginx-reverse-proxy)
10. [TLS with Let's Encrypt](#10-tls-with-lets-encrypt)
11. [Firewall Configuration](#11-firewall-configuration)
12. [Verify Deployment](#12-verify-deployment)
13. [Client Configuration](#13-client-configuration)
14. [Maintenance](#14-maintenance)
15. [Troubleshooting](#15-troubleshooting)
16. [Production Checklist](#16-production-checklist)

---

## 1. Architecture Overview

```
                        Internet
                           │
                           ▼
                   ┌───────────────┐
                   │    Nginx      │
                   │  :80 / :443  │
                   └───┬───────┬───┘
                       │       │
           /           │       │  /license/
           ▼           │       ▼
  ┌─────────────────┐  │  ┌─────────────────┐
  │  Triton Server   │  │  │ License Server   │
  │  (container)     │  │  │ (container)      │
  │  127.0.0.1:8080  │  │  │ 127.0.0.1:8081   │
  │  ┌────────────┐  │  │  │  ┌────────────┐  │
  │  │  REST API   │  │  │  │  │  Admin API  │  │
  │  │  Web UI     │  │  │  │  │  Admin UI   │  │
  │  └──────┬─────┘  │  │  │  └──────┬─────┘  │
  └─────────┼────────┘  │  └─────────┼────────┘
            │            │            │
            ▼            │            ▼
  ┌──────────────────────┴───────────────────┐
  │           PostgreSQL 18                   │
  │           127.0.0.1:5432                  │
  │                                           │
  │   DB: triton        DB: triton_license    │
  └───────────────────────────────────────────┘
```

**All services run on a single Ubuntu VM.** Only Nginx ports (80/443) are exposed to the internet. PostgreSQL and application ports stay on localhost.

**Reference sizing:**

| Metric | Recommendation |
|--------|---------------|
| Up to 100 machines | 1 vCPU, 1 GB RAM, 10 GB SSD |
| Up to 500 machines | 2 vCPU, 2 GB RAM, 20 GB SSD |
| Up to 1000+ machines | 4 vCPU, 4 GB RAM, 40 GB SSD |

---

## 2. Prerequisites

| Requirement | Details |
|-------------|---------|
| Ubuntu | 22.04 LTS or 24.04 LTS |
| Access | Root or `sudo` privileges |
| Domain name | Optional — required for Let's Encrypt TLS |
| Firewall ports | 22 (SSH), 80 (HTTP), 443 (HTTPS) |

Update the system before proceeding:

```bash
sudo apt update && sudo apt upgrade -y
```

---

## 3. Install Podman

Ubuntu 22.04+ includes Podman in the default repos:

```bash
sudo apt install -y podman
```

Verify the installation:

```bash
podman --version
```

> **Docker users:** All `podman` commands in this guide work identically with Docker. Install Docker instead with `sudo apt install -y docker.io` and replace `podman` with `docker` throughout.

---

## 4. Install Nginx

```bash
sudo apt install -y nginx
```

Enable and start Nginx:

```bash
sudo systemctl enable --now nginx
```

Verify it is running:

```bash
sudo systemctl status nginx
```

Allow HTTP and HTTPS through the firewall (full UFW setup in [Section 11](#11-firewall-configuration)):

```bash
sudo ufw allow 'Nginx Full'
```

---

## 5. Install PostgreSQL 18

### Add the PostgreSQL apt repository

```bash
sudo apt install -y curl ca-certificates
sudo install -d /usr/share/postgresql-common/pgdg
sudo curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
  https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | \
  sudo tee /etc/apt/sources.list.d/pgdg.list
sudo apt update
```

### Install and start

```bash
sudo apt install -y postgresql-18
sudo systemctl enable --now postgresql
```

### Create databases and user

Replace `STRONG_PASSWORD_HERE` with a real password:

```bash
sudo -u postgres psql <<'SQL'
CREATE USER triton WITH PASSWORD 'STRONG_PASSWORD_HERE';
CREATE DATABASE triton OWNER triton;
CREATE DATABASE triton_license OWNER triton;
GRANT ALL PRIVILEGES ON DATABASE triton TO triton;
GRANT ALL PRIVILEGES ON DATABASE triton_license TO triton;
SQL
```

### Configure local connections

Edit `pg_hba.conf` to allow password auth from localhost:

```bash
PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" | xargs)
sudo sed -i '/^local.*all.*all/s/peer/scram-sha-256/' "$PG_HBA"
```

Add a line for TCP connections from localhost (if not present):

```bash
echo "host    all    triton    127.0.0.1/32    scram-sha-256" | \
  sudo tee -a "$PG_HBA"
```

Reload the configuration:

```bash
sudo systemctl reload postgresql
```

### Verify connectivity

```bash
psql -h 127.0.0.1 -U triton -d triton -c "SELECT 1;"
```

You should be prompted for the password and see a result of `1`.

---

## 6. Pull Container Images

Pull the Triton scan server and license server images:

```bash
podman pull ghcr.io/amiryahaya/triton:latest
podman pull ghcr.io/amiryahaya/triton-license-server:latest
```

> Replace `latest` with a specific version tag (e.g., `3.0`) for reproducible deployments.

Verify the images:

```bash
podman images | grep triton
```

---

## 7. Generate Secrets

Create a directory for Triton configuration:

```bash
sudo mkdir -p /etc/triton
sudo chmod 700 /etc/triton
```

### Ed25519 keypair (license server signing)

```bash
openssl genpkey -algorithm Ed25519 -out /tmp/ed25519.pem
# Extract the raw 64-byte private key as hex
openssl pkey -in /tmp/ed25519.pem -outform DER | tail -c 64 | xxd -p -c 64 | \
  sudo tee /etc/triton/signing-key.hex > /dev/null
# Extract the 32-byte public key as hex (embed in Triton CLI builds)
openssl pkey -in /tmp/ed25519.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32 | \
  sudo tee /etc/triton/public-key.hex > /dev/null
rm /tmp/ed25519.pem
```

### Triton server API key

```bash
openssl rand -hex 32 | sudo tee /etc/triton/server-api-key.hex > /dev/null
```

Lock down permissions:

```bash
sudo chmod 600 /etc/triton/*.hex
```

---

## 8. Configure & Start Services

### Environment files

Create an env file for the Triton scan server:

```bash
sudo tee /etc/triton/triton-server.env > /dev/null <<'EOF'
TRITON_LICENSE_KEY=<your-enterprise-license-token>
EOF
sudo chmod 600 /etc/triton/triton-server.env
```

Create an env file for the license server:

```bash
# Read generated secrets
SIGNING_KEY=$(sudo cat /etc/triton/signing-key.hex)

sudo tee /etc/triton/license-server.env > /dev/null <<EOF
TRITON_LICENSE_SERVER_DB_URL=postgres://triton:STRONG_PASSWORD_HERE@127.0.0.1:5432/triton_license?sslmode=disable
TRITON_LICENSE_SERVER_LISTEN=:8081
TRITON_LICENSE_SERVER_SIGNING_KEY=${SIGNING_KEY}
TRITON_LICENSE_SERVER_ADMIN_EMAIL=admin@localhost
TRITON_LICENSE_SERVER_ADMIN_PASSWORD=CHANGE_ME_IMMEDIATELY
EOF
sudo chmod 600 /etc/triton/license-server.env
```

> Replace `STRONG_PASSWORD_HERE` with the PostgreSQL password from [Section 5](#5-install-postgresql-18). The `ADMIN_PASSWORD` is only used on first boot to seed the initial platform admin account — log in at `http://server:8081/ui/` and change the password immediately after first start.

### License server environment variables reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRITON_LICENSE_SERVER_DB_URL` | Yes | — | PostgreSQL connection URL |
| `TRITON_LICENSE_SERVER_LISTEN` | No | `:8081` | Listen address |
| `TRITON_LICENSE_SERVER_SIGNING_KEY` | Yes | — | Ed25519 private key as hex (128 hex chars) |
| `TRITON_LICENSE_SERVER_ADMIN_EMAIL` | No | `admin@localhost` | Bootstrap superadmin email (first boot only) |
| `TRITON_LICENSE_SERVER_ADMIN_PASSWORD` | Yes (first boot) | — | Bootstrap superadmin password — rotate immediately after first login |
| `TRITON_LICENSE_SERVER_TLS_CERT` | No | — | TLS cert file (not needed with Nginx) |
| `TRITON_LICENSE_SERVER_TLS_KEY` | No | — | TLS key file (not needed with Nginx) |

### Systemd unit: Triton scan server

```bash
sudo tee /etc/systemd/system/triton-server.service > /dev/null <<'EOF'
[Unit]
Description=Triton Scan Server
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
EnvironmentFile=/etc/triton/triton-server.env
ExecStartPre=-/usr/bin/podman rm -f triton-server
ExecStart=/usr/bin/podman run \
  --name triton-server \
  --rm \
  --network host \
  --env-file /etc/triton/triton-server.env \
  ghcr.io/amiryahaya/triton:latest \
  server \
    --listen 127.0.0.1:8080 \
    --db "postgres://triton:STRONG_PASSWORD_HERE@127.0.0.1:5432/triton?sslmode=disable" \
    --api-key "API_KEY_HERE"
ExecStop=/usr/bin/podman stop -t 10 triton-server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

> Replace `STRONG_PASSWORD_HERE` with your PostgreSQL password and `API_KEY_HERE` with the contents of `/etc/triton/server-api-key.hex`.

### Systemd unit: License server

```bash
sudo tee /etc/systemd/system/triton-license-server.service > /dev/null <<'EOF'
[Unit]
Description=Triton License Server
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/podman rm -f triton-license-server
ExecStart=/usr/bin/podman run \
  --name triton-license-server \
  --rm \
  --network host \
  --env-file /etc/triton/license-server.env \
  ghcr.io/amiryahaya/triton-license-server:latest
ExecStop=/usr/bin/podman stop -t 10 triton-license-server
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### Enable and start both services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now triton-server triton-license-server
```

Check status:

```bash
sudo systemctl status triton-server
sudo systemctl status triton-license-server
```

---

## 9. Configure Nginx Reverse Proxy

Create the Nginx site configuration:

```bash
sudo tee /etc/nginx/sites-available/triton > /dev/null <<'NGINX'
server {
    listen 80;
    server_name triton.yourdomain.com;

    # Scan server + Web UI
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }

    # License server + Admin UI
    location /license/ {
        rewrite ^/license/(.*) /$1 break;
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
}
NGINX
```

> Replace `triton.yourdomain.com` with your actual domain or the server's IP address.

Enable the site and disable the default:

```bash
sudo ln -sf /etc/nginx/sites-available/triton /etc/nginx/sites-enabled/triton
sudo rm -f /etc/nginx/sites-enabled/default
```

Test and reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### Port routing summary

| External Path | Nginx Routes To | Service |
|---------------|----------------|---------|
| `/` | `http://127.0.0.1:8080` | Scan server + Web UI |
| `/license/` | `http://127.0.0.1:8081` | License server + Admin UI |

---

## 10. TLS with Let's Encrypt

Install Certbot:

```bash
sudo apt install -y certbot python3-certbot-nginx
```

Obtain a certificate (requires a valid domain pointing to this server):

```bash
sudo certbot --nginx -d triton.yourdomain.com
```

Certbot will:

1. Verify domain ownership via HTTP challenge
2. Obtain a TLS certificate from Let's Encrypt
3. Automatically configure Nginx to use HTTPS
4. Set up HTTP → HTTPS redirect

### Verify auto-renewal

Certbot installs a systemd timer for automatic renewal:

```bash
sudo systemctl status certbot.timer
```

Test renewal (dry run):

```bash
sudo certbot renew --dry-run
```

### Self-signed certificate (no domain)

If you do not have a domain name, generate a self-signed certificate:

```bash
sudo openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout /etc/ssl/private/triton.key \
  -out /etc/ssl/certs/triton.crt \
  -days 365 -subj "/CN=triton-server"
```

Update the Nginx config to use it:

```nginx
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/ssl/certs/triton.crt;
    ssl_certificate_key /etc/ssl/private/triton.key;

    # ... rest of proxy config from Section 9 ...
}

server {
    listen 80;
    server_name _;
    return 301 https://$host$request_uri;
}
```

Reload Nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## 11. Firewall Configuration

Enable UFW and allow only the necessary ports:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

Verify the rules:

```bash
sudo ufw status verbose
```

Expected output:

```
Status: active

To                         Action      From
--                         ------      ----
22/tcp (OpenSSH)           ALLOW IN    Anywhere
80,443/tcp (Nginx Full)    ALLOW IN    Anywhere
```

> PostgreSQL (5432), scan server (8080), and license server (8081) are **not exposed** — they are only reachable on localhost. The `--network host` flag in the podman commands binds the containers to `127.0.0.1`, and the scan server explicitly listens on `127.0.0.1:8080`.

---

## 12. Verify Deployment

### Health checks

```bash
# Scan server (direct)
curl -s http://127.0.0.1:8080/api/v1/health

# License server (direct)
curl -s http://127.0.0.1:8081/api/v1/health

# Via Nginx (HTTP)
curl -s http://triton.yourdomain.com/api/v1/health

# Via Nginx (HTTPS, after TLS setup)
curl -s https://triton.yourdomain.com/api/v1/health

# License server via Nginx
curl -s https://triton.yourdomain.com/license/api/v1/health
```

All health endpoints should return a `200 OK` response.

### Web UI

Open in a browser:

- **Scan dashboard:** `https://triton.yourdomain.com/ui/`
- **License admin UI:** `https://triton.yourdomain.com/license/ui/`

### Create first organization and license

Log in to get a JWT token:

```bash
TOKEN=$(curl -s -X POST https://triton.yourdomain.com/license/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@localhost", "password": "your-bootstrap-password"}' \
  | jq -r .token)
```

Create an organization:

```bash
curl -s -X POST https://triton.yourdomain.com/license/api/v1/admin/orgs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Organization", "contact": "admin@myorg.com"}'
```

Note the `id` from the response, then create a license:

```bash
curl -s -X POST https://triton.yourdomain.com/license/api/v1/admin/licenses \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "orgID": "<org-uuid>",
    "tier": "enterprise",
    "seats": 10,
    "days": 365
  }'
```

Note the license `id` — this is what clients use to activate.

---

## 13. Client Configuration

On each machine that runs the Triton CLI:

### Activate a license

```bash
triton license activate \
  --license-server https://triton.yourdomain.com/license \
  --license-id <license-uuid>
```

This registers the machine with the license server and caches the licence locally at `~/.triton/license.key` with metadata at `~/.triton/license.meta`. If the server becomes unreachable, a 7-day offline grace period applies.

### Submit scans to the server

Run a scan and submit results:

```bash
triton agent \
  --server https://triton.yourdomain.com \
  --api-key "<server-api-key>" \
  --profile standard
```

For continuous scanning (every 24 hours):

```bash
triton agent \
  --server https://triton.yourdomain.com \
  --api-key "<server-api-key>" \
  --profile standard \
  --interval 24h
```

> The `<server-api-key>` must match the key in `/etc/triton/server-api-key.hex` on the server.

### Deactivate a license

To release a seat (e.g., before decommissioning a machine):

```bash
triton license deactivate \
  --license-server https://triton.yourdomain.com/license \
  --license-id <license-uuid>
```

---

## 14. Maintenance

### Upgrading container images

```bash
# Pull new versions
podman pull ghcr.io/amiryahaya/triton:latest
podman pull ghcr.io/amiryahaya/triton-license-server:latest

# Restart services (systemd will pull the updated images)
sudo systemctl restart triton-server triton-license-server
```

> Pin to specific version tags in production for controlled rollouts. Update the `ExecStart` line in the systemd units to reference the new tag.

### PostgreSQL backup

Daily backup via cron:

```bash
sudo tee /etc/cron.d/triton-backup > /dev/null <<'EOF'
0 2 * * * postgres pg_dump -Fc triton > /var/backups/triton-$(date +\%Y\%m\%d).dump
0 2 * * * postgres pg_dump -Fc triton_license > /var/backups/triton-license-$(date +\%Y\%m\%d).dump
0 3 * * * root find /var/backups -name "triton*.dump" -mtime +30 -delete
EOF
```

Create the backup directory:

```bash
sudo mkdir -p /var/backups
```

Restore from backup:

```bash
sudo -u postgres pg_restore -d triton /var/backups/triton-20260301.dump
```

### Log management

View service logs:

```bash
# Systemd journal
sudo journalctl -u triton-server -f
sudo journalctl -u triton-license-server -f

# Podman container logs
podman logs triton-server
podman logs triton-license-server
```

Systemd journal rotation is automatic. To configure retention:

```bash
sudo tee -a /etc/systemd/journald.conf > /dev/null <<'EOF'
SystemMaxUse=500M
MaxRetentionSec=30day
EOF
sudo systemctl restart systemd-journald
```

### Monitoring

Poll health endpoints from your monitoring system:

```bash
# Simple cron-based check
curl -sf https://triton.yourdomain.com/api/v1/health || \
  echo "Triton scan server is down" | mail -s "ALERT" admin@example.com
```

---

## 15. Troubleshooting

### Common issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `connection refused` on :8080 | Scan server not running | `sudo systemctl status triton-server` — check logs with `journalctl -u triton-server` |
| `connection refused` on :8081 | License server not running | `sudo systemctl status triton-license-server` — check logs |
| `502 Bad Gateway` from Nginx | Backend service not started or crashed | Verify both services are running: `podman ps` |
| `TRITON_LICENSE_SERVER_DB_URL is required` | Missing env file or empty variable | Check `/etc/triton/license-server.env` exists and has the DB URL |
| `license server has no users and no bootstrap password set` | Empty DB with no `TRITON_LICENSE_SERVER_ADMIN_PASSWORD` | Set the env var and restart the service |
| `signing key must be 64 bytes` | Incorrect signing key hex | Regenerate with the commands in [Section 7](#7-generate-secrets) — must be 128 hex characters |
| `opening database: failed to connect` | PostgreSQL not running or wrong credentials | Check `sudo systemctl status postgresql`, verify password in env files |
| `FATAL: password authentication failed` | Wrong PostgreSQL password | Reset password: `sudo -u postgres psql -c "ALTER USER triton PASSWORD 'newpass';"` |
| `permission denied for database` | Missing GRANT | Run `GRANT ALL PRIVILEGES ON DATABASE triton TO triton;` as postgres user |
| TLS certificate errors | Let's Encrypt cert expired or not issued | Run `sudo certbot renew` or check `sudo certbot certificates` |
| `404` on `/license/ui/` | Nginx rewrite not working | Verify the `rewrite` directive in the `/license/` location block |
| License activation fails | Server URL wrong or server unreachable | Verify `--license-server` URL includes `/license` path prefix |

### Diagnostic commands

```bash
# Check all services
sudo systemctl status triton-server triton-license-server postgresql nginx

# Check running containers
podman ps -a

# View container logs (last 50 lines)
podman logs --tail 50 triton-server
podman logs --tail 50 triton-license-server

# Test PostgreSQL connectivity
psql -h 127.0.0.1 -U triton -d triton -c "SELECT 1;"
psql -h 127.0.0.1 -U triton -d triton_license -c "SELECT 1;"

# Test Nginx config
sudo nginx -t

# Check what is listening on which ports
sudo ss -tlnp | grep -E '(8080|8081|5432|80|443)'

# Check firewall rules
sudo ufw status numbered
```

---

## 16. Production Checklist

- [ ] **Ubuntu updated** — `apt update && apt upgrade` completed
- [ ] **PostgreSQL credentials** — Strong password (not default `triton/triton`)
- [ ] **PostgreSQL access** — `pg_hba.conf` restricts to localhost only
- [ ] **Secrets generated** — Ed25519 keypair and server API key in `/etc/triton/`; bootstrap admin password rotated after first login
- [ ] **Secret permissions** — `/etc/triton/` is `700`, all `.hex` and `.env` files are `600`
- [ ] **Container images pinned** — Using specific version tags (not `latest`)
- [ ] **Systemd units enabled** — Both services start on boot
- [ ] **Nginx configured** — Reverse proxy with correct location blocks
- [ ] **TLS enabled** — Let's Encrypt certificate issued and auto-renewing
- [ ] **Firewall active** — UFW enabled, only SSH and Nginx Full allowed
- [ ] **Application ports internal** — 5432, 8080, 8081 bound to 127.0.0.1
- [ ] **Health checks pass** — Both `/api/v1/health` endpoints return 200
- [ ] **Web UI accessible** — Dashboard and license admin UI load in browser
- [ ] **First org + license created** — Admin API tested successfully
- [ ] **Client activation tested** — At least one CLI client activated
- [ ] **Backup cron configured** — Daily `pg_dump` with 30-day retention
- [ ] **Log rotation configured** — Journald `SystemMaxUse` set
- [ ] **Monitoring configured** — Health endpoint polling active
- [ ] **Enterprise licence set** — `TRITON_LICENSE_KEY` configured for scan server
