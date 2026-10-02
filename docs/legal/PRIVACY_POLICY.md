# PhishGuard AI — Privacy Policy

**Effective Date:** October 2, 2026  
**Compliance Standards:** India Digital Personal Data Protection (DPDP) Act, 2023 & General Data Protection Regulation (GDPR)

PhishGuard AI ("PhishGuard", "we", "our") is dedicated to safeguarding your online security while rigorously protecting your digital personal privacy. This Privacy Policy explains what information we collect, how we process it, and your rights under data protection laws.

---

## 1. Zero-PII Data Collection Principles
PhishGuard AI is architected from the ground up around a **Zero-PII** (Zero Personally Identifiable Information) logging methodology:

### What We Collect:
- **Domain Names & URL Hashes**: When scanning web destinations, we extract only the normalized domain name (e.g. `example.com`) and compute a one-way cryptographic SHA-256 hash of the URL path (`e3b0c44298fc1c...`).
- **Account Identifiers**: For registered accounts, we store your corporate email address, password hash (bcrypt), organization membership, and active plan details.
- **Client IP & User Agent**: Recorded transiently in security logs for rate limiting and fraud prevention.

### What We NEVER Collect or Store:
- We **never** store full raw URL strings containing query parameters, session tokens, or personal identifiers.
- We **never** inspect or store private email content, message bodies, or files.
- We **never** log or sell browsing history.

---

## 2. Browser Extension Permissions Justification
PhishGuard AI operates strictly within declared Chrome/Edge Manifest V3 permissions:
- `webNavigation`: Used exclusively to intercept navigation pre-flight and redirect to the interstitial warning page if a domain is flagged as dangerous.
- `storage`: Used to maintain local caching of domain verdicts (1-hour TTL) to avoid redundant external network lookups.
- `activeTab`: Used to display the security verdict of the currently focused tab in the extension popup.
- `alarms`: Used to periodically clean expired in-memory cache entries.
- `notifications`: Used to alert users when a malicious credential-theft form is detected.

---

## 3. Data Retention & Automated Purge
In compliance with the DPDP Act 2023, organizations can configure automated telemetry retention schedules (default 90 days). Once the retention window expires, scan logs are permanently purged from database disks.

---

## 4. Your Rights (DPDP Act & GDPR)
You have the right to:
- **Right to Erasure**: Request complete anonymization and deletion of your telemetry records via `POST /api/compliance/erasure-request/`.
- **Right to Access & Portability**: Export your organization's audit logs in CSV format at any time.
- **Right to Correction**: Update your account details directly in the dashboard.

---

## 5. Contact the Data Protection Officer (DPO)
For any questions regarding data privacy or to exercise your statutory rights, contact our Data Protection Officer at:  
**Email:** privacy@phishguard.ai  
**Address:** PhishGuard AI Cyber Defense Labs, Bengaluru, Karnataka, India.
