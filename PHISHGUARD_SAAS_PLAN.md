# PhishGuard SaaS: Antigravity Build Plan

**Goal:** Turn the local PhishGuard prototype into a hosted, paid SaaS (Free / Pro / Team / Enterprise), targeting Indian BFSI, fintech and SMB customers.

**How to use this file in Antigravity**
1. Save the "Workspace Rules" block below as a workspace rule so every agent follows it.
2. Run **one phase at a time**. Paste the phase's *Agent Prompt* into the Agent Manager.
3. Ask the agent for an **Implementation Plan artifact first**, review it, then approve execution.
4. A phase is done only when its **Acceptance Criteria** pass and tests are green. Commit, then move on.
5. Run independent phases in parallel agents only where marked (⚡).

---

## Workspace Rules

```
Project: PhishGuard AI. Chrome MV3 extension + Django 5/DRF backend + sklearn model.
Stack target: Python 3.11, Django 5, DRF, PostgreSQL, Redis, Celery, Docker, Razorpay.
Rules:
- Never hardcode secrets. Use env vars (python-dotenv / django-environ). Provide .env.example.
- Every new feature needs unit tests (pytest + pytest-django). Do not mark done with failing tests.
- Never store full URLs containing query tokens/PII in logs or DB; store domain + hashed full URL.
- Keep extension permissions minimal. Justify any new permission in the PR notes.
- Small commits per task, conventional commit messages.
- Before big changes, produce an Implementation Plan and wait for approval.
- Do not change the ML model's public predict interface without updating tests.
```

---

## Target Architecture

```
Extension (MV3) ──HTTPS + API key/JWT──> Django/DRF API ──> Postgres
                                              │──> Redis (cache, throttle, queue)
                                              │──> Celery workers (WHOIS/SSL/feeds/model retrain)
                                              └──> Detection engine (ML + intel + domain + rules)
Web dashboard (Django templates or React) ── Orgs, users, billing, reports
Razorpay/Stripe webhooks ──> Subscription state ──> Plan limits
```

---

## Phase 0: Baseline and Safety Net
**Goal:** Make the existing code testable and safe to refactor.

Tasks
- Add `pytest`, `pytest-django`, `ruff`, `pre-commit`.
- Tests for `normalize_url`, rule adjustments (whitelist, HTTPS, keywords), thresholds, and `/api/check-url/` (valid, invalid, empty, huge payload).
- Move model loading into a singleton / `AppConfig.ready()` with a clear error if the `.joblib` is missing.
- Split settings: `base.py`, `dev.py`, `prod.py`.
- Add GitHub Actions: lint + test on push.

Acceptance Criteria
- `pytest` passes with ≥70% coverage on `scanner/`.
- App starts with a friendly error (not a crash) if the model file is missing.
- CI is green.

**Agent Prompt**
> Read the whole repo. Produce an Implementation Plan to add a pytest suite, split settings into base/dev/prod, refactor model loading into a singleton loaded in AppConfig.ready(), and add a GitHub Actions CI workflow. Do not change prediction behavior. Then execute after approval and show test results.

---

## Phase 1: Accounts, Orgs, API Keys, Throttling
**Goal:** Know who is calling and limit them by plan.

Tasks
- Models: `Organization`, `Membership(role: owner/admin/member)`, `Plan`, `Subscription`, `APIKey` (hashed, prefix shown), `UsageLog`.
- Auth: email+password, Google SSO (django-allauth), JWT for the extension (short-lived access + refresh).
- Extension login flow via a web login page that returns a token (`chrome.identity` or a redirect flow).
- DRF custom throttle reading limits from the user's plan (Free 20/day, Pro unlimited with a fair-use cap).
- Lock CORS to the extension ID; remove `CORS_ALLOW_ALL_ORIGINS`.
- `/api/check-url/` requires auth; anonymous gets a tiny trial quota by IP.

Acceptance Criteria
- Unauthenticated calls beyond the trial quota return 401/429.
- Free user hits the 21st scan in a day → 429 with a clear JSON message.
- API keys are stored hashed; the plaintext is shown only once.
- Tests cover auth, throttling per plan, and key revocation.

---

## Phase 2: Hosted Deployment ⚡ (parallel with Phase 3)
**Goal:** A real HTTPS API the extension can call.

Tasks
- `Dockerfile` + `docker-compose.yml` (web, postgres, redis, celery, nginx/caddy).
- Switch SQLite → Postgres. Config via env.
- Gunicorn, WhiteNoise, secure cookies, HSTS, `DEBUG=False` checks (`manage.py check --deploy`).
- Deploy target: a VPS (Hetzner/DigitalOcean/AWS Mumbai) with Caddy for auto-HTTPS. Use an India region for the data-residency pitch.
- CI/CD: build image → push → SSH/deploy on main. Add Sentry and an uptime check.
- Update the extension `manifest.json` host permissions to the production domain.

Acceptance Criteria
- `https://api.<yourdomain>/api/health/` returns 200.
- `check --deploy` shows no critical warnings.
- Zero-downtime redeploy documented in `DEPLOY.md`.

---

## Phase 3: Detection Engine v2 ⚡
**Goal:** Build the real moat. Stop relying only on TF-IDF.

Tasks
1. **Threat intel:** Celery tasks syncing OpenPhish, PhishTank, URLhaus into Postgres/Redis. Optional Google Safe Browsing and VirusTotal lookups (cached).
2. **Domain features:** WHOIS/domain age, SSL cert age and issuer, DNS records, TLD risk, IP-in-URL, subdomain depth/entropy, punycode/homoglyph detection, URL shortener unwrapping, redirect-chain follow (with SSRF protection!).
3. **Brand-lookalike module:** Maintain a list of Indian brands (HDFC, SBI, ICICI, Axis, Paytm, PhonePe, UPI, IRCTC, India Post, income-tax, etc.). Flag Levenshtein/keyword impersonation.
4. **Model v3:** Gradient boosting (LightGBM/XGBoost) on structural features + TF-IDF model probability as a stacked feature. Version models (`model_version` field in results).
5. **Scoring orchestrator:** Combine all signals into a final score with a **reasons list** and per-signal weights. Keep it explainable.
6. **Security note:** Any server-side URL fetching must block private IP ranges, enforce timeouts and size limits, and never follow redirects into internal networks.

Acceptance Criteria
- Known phishing URLs from the feeds are flagged `phishing` with the reason "Listed in threat feed X".
- `hdfc-secure-login.xyz` flags as a brand lookalike.
- A benchmark script reports precision/recall on a held-out set. Model v3 beats v2.
- Fetcher passes SSRF tests (`127.0.0.1`, `169.254.169.254`, `10.x` blocked).

---

## Phase 4: Extension v2
**Goal:** Protection that works automatically, not only on button click.

Tasks
- Service worker listens with `webNavigation.onBeforeNavigate` / `declarativeNetRequest` and checks the URL before load.
- Interstitial **warning page** ("Dangerous site: Go back / Proceed anyway") with reasons.
- Local cache in `chrome.storage.local` (domain verdict, TTL 1h) plus a bundled allowlist of top domains to skip calls.
- **Content script:** detect password/OTP fields on suspicious domains, forms posting cross-domain, hidden iframes.
- **Credential-entry protection:** Warn on password typing at unknown or risky domains.
- Login/logout, plan badge, remaining quota, a "Report phishing / false positive" button.
- Badge icon colour per page verdict.
- Drop the `tabs` permission if `activeTab` is enough. Write the privacy-policy text.

Acceptance Criteria
- Visiting a known test phishing URL shows the interstitial before the page renders.
- Cached domains cause no API call (verify in the network log).
- Extension works on Chrome and Edge; build script produces a zip for the Web Store.

---

## Phase 5: Billing (Razorpay + Stripe)
**Goal:** Actually charge money.

Tasks
- Plans: Free, Pro, Team (per-seat), Enterprise (manual invoice).
- Razorpay Subscriptions (UPI/cards) for India; Stripe for international.
- Webhooks (signature verified, idempotent) update `Subscription` status: active, past_due, cancelled.
- Billing page: upgrade, cancel, invoices; GST fields for Indian businesses.
- Grace period on failed payment, then downgrade to Free.
- Feature flags driven by plan (`plan.features`), enforced in the API, not just the UI.

Acceptance Criteria
- Test-mode subscription upgrades the user to Pro within seconds via webhook.
- Replaying the same webhook doesn't double-apply.
- Cancelling reverts limits at period end.

---

## Phase 6: Team Dashboard and Reporting
**Goal:** The feature enterprises pay for: visibility.

Tasks
- Web dashboard (Django + HTMX/Tailwind, or React): org overview, scans over time, top blocked domains, most-targeted users, incident timeline.
- Admin policy: org allowlist/blocklist, block-vs-warn mode, force-enable for members.
- Invite members by email, role management, seat billing.
- Employee reports queue: review, mark true/false positive, feed into the retraining dataset.
- Alerts: email + Slack webhook on high-risk hits.
- Export CSV and PDF report.

Acceptance Criteria
- Admin sees only their own org's data (add tenant-isolation tests).
- Allowlisting a domain changes extension behaviour for all members within the cache TTL.

---

## Phase 7: Email Link Scanning (biggest upgrade driver)
**Goal:** Catch phishing where it starts.

Tasks
- Content script for Gmail and Outlook Web: scan links in the opened email and badge risky ones (inline warning).
- Optional later: Gmail add-on / Microsoft Graph integration for org-wide mailbox scanning.
- Show sender-domain vs link-domain mismatch as a signal.
- Bulk `POST /api/check-urls/` endpoint (batch, capped) with caching.

Acceptance Criteria
- Opening an email with a seeded phishing link shows an inline warning within 2s.
- Batch endpoint handles 50 URLs under plan limits.

---

## Phase 8: Enterprise and Compliance
**Goal:** Win banks and larger customers.

Tasks
- SAML/OIDC SSO (Okta, Azure AD), SCIM optional.
- Immutable audit log (who changed policy, who viewed reports).
- SIEM export: syslog/webhook to Splunk/Sentinel; REST API with scoped keys.
- Data retention controls, data deletion on request, DPDP Act-aligned privacy documentation.
- Optional on-prem/private-cloud Docker bundle.
- Security hardening: dependency scanning, SAST, pen-test checklist, backup/restore runbook.

Acceptance Criteria
- SSO login works against a test IdP.
- Audit log entries are append-only and exportable.
- A security whitepaper and DPA template exist in `/docs`.

---

## Phase 9: Launch Checklist
- [ ] Landing page with pricing, demo video, and a free trial CTA
- [ ] Privacy policy, Terms, Refund policy (required by Razorpay and the Chrome Web Store)
- [ ] Chrome Web Store listing: screenshots, permission justifications, privacy practices
- [ ] Edge Add-ons and Firefox ports
- [ ] Onboarding email sequence and in-extension tour
- [ ] Status page, support email, and error alerting
- [ ] 10 pilot users (co-op banks, fintech startups, CA/accounting firms) before public launch
- [ ] Track: activation, scans per user, free→paid conversion, false-positive rate
