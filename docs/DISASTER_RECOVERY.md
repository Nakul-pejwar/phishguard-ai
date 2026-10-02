# PhishGuard AI — Disaster Recovery & Backup Runbook

**Target SLA:** 99.9% Uptime  
**Recovery Point Objective (RPO):** $\le 1\text{ hour}$  
**Recovery Time Objective (RTO):** $\le 15\text{ minutes}$

---

## 1. Architecture Resilience & Redundancy

```
[ DNS / Anycast Routing ]
          │
    ┌─────┴─────┐
    ▼           ▼
[ Primary ] [ Standby ] (Hot-Standby Docker / K8s Nodes)
    │           │
    ▼           ▼
[ Postgres Primary ] ──(WAL Streaming Replication)──> [ Postgres Read Replica ]
    │
    ▼ (Nightly Encrypted Snapshots)
[ S3 / Cloud Storage Glacier Backup ]
```

---

## 2. Automated Backup Strategy

### Database Snapshots (PostgreSQL 16):
- **Continuous Archiving**: Write-Ahead Logging (WAL-G) streaming to encrypted S3 bucket.
- **Nightly Logical Dump**: Automated `pg_dump` executed via cron at 02:00 UTC:
  ```bash
  pg_dump -h localhost -U phishguard_user -d phishguard_db | gzip | \
    aws s3 cp - s3://phishguard-backups/pg-$(date +%Y%m%d_%H%M%S).sql.gz --sse aws:kms
  ```
- **Retention Schedule**: 30 daily snapshots, 12 monthly archives.

### Threat Intel Cache & Redis:
- Redis RDB snapshots persisted to persistent volume every 15 minutes.
- Threat feeds automatically re-synchronize from source upon fresh startup.

---

## 3. Disaster Recovery & Restoration Procedures

### Scenario A: PostgreSQL Database Corruption / Accidental Loss
1. **Stop Active Worker & Backend Services**:
   ```bash
   docker compose stop backend worker beat
   ```
2. **Retrieve Latest Encrypted Snapshot**:
   ```bash
   aws s3 cp s3://phishguard-backups/latest-clean.sql.gz ./restore/
   gunzip ./restore/latest-clean.sql.gz
   ```
3. **Restore Database**:
   ```bash
   docker compose exec -T db psql -U phishguard_user -d phishguard_db < ./restore/latest-clean.sql
   ```
4. **Run Pending Migrations**:
   ```bash
   docker compose run --rm backend python manage.py migrate
   ```
5. **Restart Application Cluster**:
   ```bash
   docker compose up -d
   ```
6. **Verify System Health**:
   ```bash
   curl -I http://localhost:8000/api/health/
   ```

### Scenario B: Complete Host Failover
1. Launch secondary standby instance via Terraform / Cloud Provider.
2. Mount latest snapshot volume or pull Docker images from registry.
3. Update DNS CNAME / A-records to point to secondary host.
4. Verify HTTPS certificate auto-provisioning via Caddy.

---

## 4. Disaster Recovery Testing Schedule
- **Bi-annual Simulation**: Staging environment restored from production snapshot every 6 months to validate RTO $\le 15\text{ mins}$.
- **Checksum Verification**: Daily automated SHA-256 integrity checks on stored database archives.
