# PhishGuard AI — Production Deployment Guide

This document details the production setup, infrastructure architecture, environment configuration, zero-downtime redeploy workflows, and disaster recovery procedures for **PhishGuard AI**.

---

## 1. Production Architecture Overview

The hosted stack runs containerized via **Docker Compose**:
- **Caddy**: Edge reverse proxy handling automated TLS certificate management via Let's Encrypt, security headers, and compression.
- **Django + Gunicorn**: API backend running with production settings, WhiteNoise static compression, and PostgreSQL backend.
- **PostgreSQL 16**: Primary relational database for multi-tenant accounts, memberships, subscriptions, API keys, and privacy-compliant scan audit logs.
- **Redis 7**: Distributed cache and Celery broker.
- **Celery Workers & Beat**: Async worker fleet for threat intelligence feed ingestion, WHOIS/SSL domain enrichment, and model background jobs.

---

## 2. Server Provisioning & Prerequisites

### Recommended Specifications:
- **Target Hosting**: AWS Mumbai (`ap-south-1`) or Hetzner VPS (for Indian data residency compliance).
- **Compute**: 2 vCPU, 4GB RAM minimum (8GB recommended for production ML training).
- **OS**: Ubuntu 22.04 LTS / 24.04 LTS.
- **Docker & Compose**: Docker 25.x+ and Docker Compose v2.x.

### Step 1: Install Docker on Host
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update && sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

---

## 3. Environment Configuration

1. Clone the repository on the target server:
   ```bash
   git clone <repo-url> /opt/phishguard
   cd /opt/phishguard
   ```

2. Configure production `.env`:
   ```bash
   cp .env.example .env
   ```

3. Populate production values:
   ```env
   DJANGO_ENV=prod
   SECRET_KEY=generate-a-strong-random-64-char-secret-key
   DEBUG=False
   ALLOWED_HOSTS=api.phishguard.ai,app.phishguard.ai
   POSTGRES_DB=phishguard
   POSTGRES_USER=phishguard_admin
   POSTGRES_PASSWORD=use-a-strong-database-password
   CORS_ALLOWED_ORIGINS=https://app.phishguard.ai,https://phishguard.ai
   DOMAIN=api.phishguard.ai
   ACME_EMAIL=ops@phishguard.ai
   SECURE_SSL_REDIRECT=True
   ```

---

## 4. Bootstrapping & First-Time Launch

1. Start all container services:
   ```bash
   docker compose up -d --build
   ```

2. Run initial database migrations:
   ```bash
   docker compose exec web python manage.py migrate
   ```

3. Create superuser:
   ```bash
   docker compose exec web python manage.py createsuperuser
   ```

4. Verify healthcheck:
   ```bash
   curl -i https://api.phishguard.ai/api/health/
   ```
   Expected response (`200 OK`):
   ```json
   {
     "status": "healthy",
     "database": "connected",
     "model_loaded": true,
     "version": "1.0.0",
     "timestamp": "2026-10-01T10:00:00Z"
   }
   ```

---

## 5. Zero-Downtime Rolling Redeploy

To deploy a new code release without dropping connections:

```bash
# 1. Pull latest code
git pull origin main

# 2. Build new images
docker compose build web celery_worker celery_beat

# 3. Run database migrations safely
docker compose run --rm web python manage.py migrate

# 4. Restart web and worker containers
docker compose up -d --no-deps web celery_worker celery_beat
```

---

## 6. Backup & Recovery Runbook

### Automated Daily Database Backup
Add a daily cron job on the host:
```bash
0 2 * * * docker compose -f /opt/phishguard/docker-compose.yml exec -T db pg_dump -U phishguard_admin phishguard | gzip > /opt/backups/phishguard_$(date +\%F).sql.gz
```

### Database Restore Procedure
```bash
gunzip < /opt/backups/phishguard_2026-10-01.sql.gz | docker compose exec -T db psql -U phishguard_admin -d phishguard
```

---

## 7. Security Hardening Checklist

- [x] `DEBUG = False` enforced in `settings/prod.py`.
- [x] Database credentials passed strictly via environment variables.
- [x] SSL/HSTS headers enforced via Caddy and Django Security Middleware.
- [x] CORS locked down to authenticated origins and browser extensions.
- [x] Non-root execution in Docker container.
- [x] Health check probes enabled on web container and reverse proxy.
