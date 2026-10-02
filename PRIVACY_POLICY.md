# PhishGuard AI — Privacy Policy

**Last Updated:** October 2026

PhishGuard AI ("PhishGuard", "we", "our", or "us") provides a browser extension and SaaS platform engineered to protect users and enterprise organizations against phishing websites, brand impersonation, fraudulent domains, and credential theft.

We respect your privacy and adhere strictly to global data protection standards, including the **Digital Personal Data Protection (DPDP) Act of India** and Google Chrome Web Store Developer Privacy Requirements.

---

## 1. Information We Collect and How We Use It

### A. URL Security Scanning
When you navigate the web with PhishGuard real-time protection enabled:
- **Domain-Level Filtering:** Well-known, trusted domains (e.g., `google.com`, `github.com`, `hdfcbank.com`) are matched against a static local allowlist inside your browser. No data is transmitted for these domains.
- **Hash-Based Privacy Preservation:** When scanning unknown or suspicious URLs, PhishGuard converts sensitive query parameters into a one-way **SHA-256 hash** or extracts the domain alone.
- **No Keystroke / PII Logging:** PhishGuard never logs, stores, or transmits passwords, credit card numbers, OTPs, or personally identifiable form contents.

### B. Account & Subscription Information
When you create a PhishGuard account:
- We collect your name, email address, password hash (via PBKDF2/Argon2), organization name, and subscription tier.
- This data is used solely to authenticate your session, enforce plan throttling limits, and provide security reports.

---

## 2. Permissions Justification (Chrome Extension MV3)

| Permission | Purpose & Justification |
|---|---|
| `webNavigation` | Required to intercept navigation to deceptive phishing URLs before malicious HTML renders. |
| `storage` | Stores your session authentication token, local 1-hour domain verdict cache, and real-time settings locally. |
| `activeTab` | Allows the extension popup to display the safety score of the page you are currently viewing. |
| `notifications` | Alerts you when a dangerous website or credential harvesting attempt is blocked. |

---

## 3. Data Retention and Security
- Scanned domain metrics and telemetry are stored in an encrypted database for security benchmarking and false-positive resolution.
- Enterprise customers have full control to request automated data purging after 30, 60, or 90 days.
- User accounts may be deleted at any time with all associated API keys and logs permanently erased.

---

## 4. Contact Information
For privacy inquiries, security reports, or data deletion requests, contact:
- **Security & Privacy Team:** privacy@phishguard.ai
- **Website:** https://phishguard.ai
