# PhishGuard AI - VPS Deployment & Extension Distribution Guide

This guide walks you through deploying **PhishGuard AI** on a Linux VPS (DigitalOcean, AWS EC2, Linode, Hetzner, Vultr, Contabo, etc.) with automated SSL and direct browser extension downloads.

---

## 1. Prerequisites

- A Linux VPS running **Ubuntu 22.04 / 24.04 LTS** or **Debian 11 / 12**.
- Open Firewall / Security Group Ports:
  - **Port 80** (HTTP)
  - **Port 443** (HTTPS)
- (Optional) A domain name pointing to your VPS IP (e.g. `phishguard.ai` or `subdomain.yourdomain.com`).

---

## 2. 1-Click VPS Deployment

SSH into your VPS as `root` (or sudo user) and execute:

```bash
# 1. Clone your PhishGuard repository
git clone https://github.com/Nakul-pejwar/phishguard-ai.git /var/www/phishguard-ai
cd /var/www/phishguard-ai

# 2. Make the deployment script executable
chmod +x deploy/deploy_vps.sh

# 3. Run the automated deployment script
sudo ./deploy/deploy_vps.sh
```

The script will automatically:
1. Install Docker, Docker Compose, and dependencies if not already present.
2. Prompt for your domain or VPS IP (e.g. `phishguard.ai`).
3. Generate secure database credentials and cryptographic secrets.
4. Package the latest Chrome and Firefox browser extensions into `dist/`.
5. Build and launch the container stack (Postgres, Redis, Celery, Django Gunicorn, Caddy).
6. Apply database migrations and provision automatic Let's Encrypt SSL certificates.

---

## 3. How the "Add to Chrome" Flow Works on Your VPS

When any visitor lands on your website (`https://your-domain.com`):
1. **Clicking "Add to Chrome — Free"**:
   - Triggers an instant download of `phishguard-chrome-v2.0.0.zip` directly from your VPS (`/downloads/phishguard-chrome-v2.0.0.zip`).
   - Opens the sleek **Guided Setup Modal** explaining the 3 quick steps:
     - **Step 1:** Extract the downloaded `.zip` file.
     - **Step 2:** Open `chrome://extensions` (1-click copy button included).
     - **Step 3:** Enable **Developer mode** and click **Load unpacked**.
2. **Switching to Edge or Firefox**:
   - The modal dynamically updates the instructions and download package for Microsoft Edge or Firefox Add-ons.
3. **Optional Chrome Web Store Link**:
   - Once published to the Chrome Web Store, you can configure `window.CHROME_STORE_URL = "https://chromewebstore.google.com/detail/..."` in `landing/script.js` to redirect directly to the official 1-click install.

---

## 4. Useful Management Commands on VPS

```bash
# View live container logs (Caddy, Django, Celery)
docker compose logs -f

# Check container health status
docker compose ps

# Restart the stack
docker compose restart

# Update code & rebuild after git pull
git pull
python3 scripts/package_extension.py
docker compose up -d --build
```
