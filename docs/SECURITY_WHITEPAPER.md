# PhishGuard AI — Enterprise Security Whitepaper

**Document Version:** 2.0.0  
**Target Audience:** Chief Information Security Officers (CISOs), SOC Leads, IT Security Architects, and Enterprise Risk Teams.

---

## 1. Executive Summary
PhishGuard AI provides real-time, zero-latency protection against credential harvesting, phishing domains, Indian BFSI brand impersonations, and email link spoofing attacks. Built specifically for high-compliance environments (BFSI, fintech, healthcare, and enterprise SMBs), PhishGuard delivers threat mitigation directly within web browsers (Chrome/Edge MV3) and email clients (Gmail/Outlook Web) without sacrificing user privacy or data security.

---

## 2. Multi-Signal Threat Detection Architecture

```
                               ┌─────────────────────────────┐
                               │       Incoming URL /        │
                               │      Email Link Event       │
                               └──────────────┬──────────────┘
                                              │
               ┌──────────────────────────────┼──────────────────────────────┐
               ▼                              ▼                              ▼
    ┌────────────────────┐         ┌────────────────────┐         ┌────────────────────┐
    │  Threat Intel Feeds│         │ Indian Lookalike   │         │ Sender Domain      │
    │  (OpenPhish / URLH)│         │ & Typosquat Engine │         │ Spoofing Engine    │
    └──────────┬─────────┘         └──────────┬─────────┘         └──────────┬─────────┘
               │                              │                              │
               └──────────────────────────────┼──────────────────────────────┘
                                              │
                                              ▼
                               ┌─────────────────────────────┐
                               │   Multi-Signal Synthesizer  │
                               │   (Explainable ML Verdict)  │
                               └──────────────┬──────────────┘
                                              │
                                              ▼
                               ┌─────────────────────────────┐
                               │   Action: Interstitial /    │
                               │   SIEM Alert / Audit Log    │
                               └─────────────────────────────┘
```

### Core Threat Signal Engines:
1. **Threat Intel Ingestion Engine**: Near real-time synchronization with active global feeds (OpenPhish, URLhaus) with SHA-256 pre-computed hash matching in memory.
2. **Indian BFSI Brand Impersonation**: Levenshtein distance metrics + semantic keyword analysis specifically tuned for major Indian financial institutions (HDFC, SBI, ICICI, Axis, Kotak, Paytm, PhonePe, UPI/NPCI, UIDAI).
3. **Sender-to-Link Spoofing Analysis**: Evaluates whether an email claims to originate from a recognized banking or corporate domain while diverting users to an unverified external or lookalike destination.
4. **Resilient ML Classifier**: Pre-trained TF-IDF Logistic Regression pipeline with heuristic fallback redundancy guaranteeing zero downtime.

---

## 3. Privacy-First Data Architecture (Zero-PII)
PhishGuard operates on a strict **Zero-PII** (Personally Identifiable Information) security architecture:
- **No Raw URL Storage**: Database logs only preserve the normalized domain name and the one-way `SHA-256(clean_url)` hash. Query parameters, authentication tokens, session IDs, and personal identifiers never reach disk.
- **Client-Side Sanitization**: Browser extensions evaluate trusted allowlists locally, avoiding unnecessary external network lookups for top global and Indian institutions.
- **Tenant Isolation**: Multi-tenant database schemas isolate usage analytics, custom policies, incident reports, and audit logs by enterprise organization boundaries.

---

## 4. Enterprise Identity & Access Management
- **SAML 2.0 / OIDC SSO**: Direct federation with Okta, Microsoft Azure AD (Entra ID), Google Workspace, and Ping Identity.
- **Just-In-Time (JIT) Provisioning**: Automated seat assignment based on enterprise email domains.
- **Role-Based Access Control (RBAC)**: Distinct permissions for `Owner`, `Admin`, and `Member` roles.
- **Dual Authentication**: Scoped cryptographic API Keys (`pg_live_...` with SHA-256 validation) and short-lived JWT session tokens.

---

## 5. Governance, SIEM Integration & Auditability
- **Immutable Audit Logging**: Append-only audit trails record all administrative actions, policy adjustments, user additions/removals, and triage operations.
- **Real-Time SIEM Streaming**: Asynchronous event dispatchers stream high-risk security incidents to Splunk HEC, Microsoft Sentinel, Datadog, or custom SOC webhooks.
- **Indian DPDP Act (2023) Compliance**: Automated data retention policies with configurable TTLs (default 90 days) and right-to-erasure endpoints for full regulatory alignment.

---

## 6. Encryption & Infrastructure Hardening
- **Data in Transit**: TLS 1.3 enforced across all web, API, and extension communication.
- **Data at Rest**: AES-256 encryption on database volumes and credentials.
- **Container Isolation**: Multi-stage, non-root Docker runtime with Caddy reverse proxy and automatic Let's Encrypt TLS renewal.
- **SSRF Defense**: Strict loopback and internal IP blocking on all external fetch operations.
