#!/usr/bin/env bash
# ==============================================================================
# PhishGuard AI — Safe VPS Release Sync Script
# Ensures safe, clean updates from GitHub main branch without accidental overwrites
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=========================================================="
echo "🛡️  PhishGuard AI — Safe VPS Sync & Release"
echo "=========================================================="

# 1. Verify working directory is clean
if [ -n "$(git status --porcelain)" ]; then
  echo "[-] ERROR: VPS working tree has uncommitted local changes or is dirty."
  echo "[-] Local changes on VPS violate the deployment workflow."
  echo ""
  echo "    To inspect modified files:  git status"
  echo "    To discard local changes:   git reset --hard HEAD"
  echo "    To stash local changes:     git stash"
  echo ""
  echo "Aborting sync."
  exit 1
fi

echo "[+] Working tree is clean."

# 2. Fetch and rebase from origin main
echo "[+] Fetching latest release from GitHub origin/main..."
git fetch origin main
git pull --rebase origin main

echo "[+] Git repository successfully updated to commit: $(git rev-parse --short HEAD)"

# 3. Read domain / API URL from .env if available
DOMAIN=""
if [ -f .env ]; then
  DOMAIN=$(grep -E "^DOMAIN=" .env | cut -d '=' -f2 | tr -d '"' | tr -d "'" || true)
fi

# 4. Regenerate extension distribution packages
if [ -n "${DOMAIN}" ] && [ "${DOMAIN}" != "localhost" ]; then
  PROTOCOL="https"
  if [[ "${DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    PROTOCOL="http"
  fi
  echo "[+] Re-packaging browser extensions with API base -> ${PROTOCOL}://${DOMAIN}..."
  python3 scripts/package_extension.py --api-url "${PROTOCOL}://${DOMAIN}" || python scripts/package_extension.py --api-url "${PROTOCOL}://${DOMAIN}" || echo "[!] Extension packaging skipped."
else
  echo "[+] Re-packaging browser extensions with default configuration..."
  python3 scripts/package_extension.py || python scripts/package_extension.py || echo "[!] Extension packaging skipped."
fi

echo ""
echo "=========================================================="
echo "✅ Safe sync completed successfully."
echo "   Next steps to apply changes to running containers:"
echo "   1. docker compose build && docker compose up -d"
echo "   2. docker compose exec -T web python manage.py migrate --noinput"
echo "   3. curl -s http://127.0.0.1:8093/api/health/"
echo "=========================================================="
