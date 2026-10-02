#!/usr/bin/env bash
# ==============================================================================
# PhishGuard AI — 1-Click VPS Deployment Script
# Supports: Ubuntu 22.04 / 24.04 LTS, Debian 11 / 12
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo "🛡️  PhishGuard AI — Enterprise VPS Deployment"
echo "=========================================================="

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root (or use: sudo ./deploy/deploy_vps.sh)"
  exit 1
fi

# 2. Install Docker & Docker Compose if missing
if ! command -v docker &> /dev/null; then
  echo "[+] Installing Docker Engine..."
  apt-get update
  apt-get install -y ca-certificates curl gnupg lsb-release zip unzip
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# 3. Prompt for Domain / VPS IP Configuration
read -p "Enter your Domain Name or VPS IP (e.g. phishguard.ai or 192.168.1.100) [localhost]: " USER_DOMAIN
USER_DOMAIN=${USER_DOMAIN:-localhost}

read -p "Enter your SSL Admin Email for Let's Encrypt [admin@$USER_DOMAIN]: " USER_EMAIL
USER_EMAIL=${USER_EMAIL:-admin@$USER_DOMAIN}

# 4. Generate Production .env if missing
if [ ! -f .env ]; then
  echo "[+] Generating production .env configuration..."
  SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(50))" 2>/dev/null || openssl rand -base64 48)
  POSTGRES_PW=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))" 2>/dev/null || openssl rand -base64 24)

  cat > .env <<EOL
DJANGO_ENV=prod
SECRET_KEY=${SECRET_KEY}
DEBUG=False
DOMAIN=${USER_DOMAIN}
ACME_EMAIL=${USER_EMAIL}
ALLOWED_HOSTS=${USER_DOMAIN},localhost,127.0.0.1
POSTGRES_DB=phishguard
POSTGRES_USER=phishguard
POSTGRES_PASSWORD=${POSTGRES_PW}
DATABASE_URL=postgres://phishguard:${POSTGRES_PW}@db:5432/phishguard
REDIS_URL=redis://redis:6379/0
CORS_ALLOWED_ORIGINS=https://${USER_DOMAIN},http://${USER_DOMAIN}
SECURE_SSL_REDIRECT=False
EOL
  echo "[+] .env generated successfully."
fi

# 5. Build Distribution Packages for Direct Download (Pre-configured with VPS Backend URL)
echo "[+] Packaging Chrome & Firefox browser extensions configured for ${USER_DOMAIN}..."
PROTOCOL="https"
if [[ "${USER_DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [ "${USER_DOMAIN}" = "localhost" ]; then
  PROTOCOL="http"
fi
python3 scripts/package_extension.py --api-url "${PROTOCOL}://${USER_DOMAIN}" 2>/dev/null || python scripts/package_extension.py --api-url "${PROTOCOL}://${USER_DOMAIN}" 2>/dev/null || echo "[!] Extension zip packaging skipped (packages will use existing dist/ files)."


# 6. Build and Launch Containers
echo "[+] Starting PhishGuard production container stack..."
docker compose down --remove-orphans || true
docker compose build
docker compose up -d

# 7. Apply Database Migrations & Collect Static
echo "[+] Running database migrations..."
docker compose exec -T web python manage.py migrate --noinput
docker compose exec -T web python manage.py collectstatic --noinput || true

echo "=========================================================="
echo "✅  PhishGuard AI Successfully Deployed!"
echo "=========================================================="
echo "🌐  Landing Page & Downloader : http://${USER_DOMAIN} (or https://${USER_DOMAIN})"
echo "⚡  API Health Check          : http://${USER_DOMAIN}/api/health/"
echo "📦  Direct Chrome Extension   : http://${USER_DOMAIN}/downloads/phishguard-chrome-v2.0.0.zip"
echo "📦  Direct Firefox Extension  : http://${USER_DOMAIN}/downloads/phishguard-firefox-v2.0.0.zip"
echo "=========================================================="
