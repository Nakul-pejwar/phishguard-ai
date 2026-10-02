# PhishGuard AI — Data Processing Agreement (DPA)

**Framework:** India Digital Personal Data Protection (DPDP) Act, 2023 & General Data Protection Regulation (GDPR)  
**Effective Date:** Upon execution or enterprise subscription agreement  
**Parties:**
1. **Data Fiduciary / Data Controller ("Customer" / "Enterprise")**
2. **Data Processor ("PhishGuard AI" / "Service Provider")**

---

## 1. Scope and Purpose of Processing
PhishGuard AI processes telemetry strictly to provide real-time cybersecurity protection against phishing, brand spoofing, and fraud.

### Categories of Data Processed:
- **Scan Telemetry**: Domain name (e.g. `example.com`), SHA-256 hash of URL path (`e3b0c442...`), scan timestamp, and verdict (Safe / Suspicious / Phishing).
- **User Identifiers**: Business email address, user ID, role, and corporate organization affiliation.
- **Administrative Audit Records**: Timestamped logs of policy changes, user additions, and incident triage.

### Explicit Non-Processing:
- PhishGuard **does NOT** record full raw URL strings containing query parameters or sensitive tokens.
- PhishGuard **does NOT** inspect private email message bodies or browser browsing history outside explicit scan events.

---

## 2. Obligations of the Data Processor (PhishGuard AI)
1. **Purpose Limitation**: Process digital personal data solely on documented instructions of the Customer for cybersecurity threat analysis.
2. **Technical and Organizational Measures (TOMs)**:
   - Encrypt data in transit using TLS 1.3 and at rest using AES-256.
   - Enforce multi-tenant database isolation.
   - Maintain immutable append-only audit trails.
3. **Data Retention & Automated Purge**:
   - Telemetry data is automatically deleted upon expiration of the organization's retention schedule (default 90 days).
4. **Assistance with Data Principal Rights (DPDP Act)**:
   - Provide administrative tooling and API endpoints for Right to Erasure, Correction, and Access within 48 hours of request.
5. **Incident Notification**:
   - Notify the Customer without undue delay (and within 24 hours) upon confirming any security incident involving Customer data.

---

## 3. Sub-Processors
PhishGuard AI utilizes trusted enterprise cloud infrastructure providers (e.g., AWS / Azure / GCP) located in compliant Indian and global regions. All sub-processors are bound by equivalent confidentiality and data protection obligations.

---

## 4. Term and Termination
Upon termination of services, Customer may export all audit logs and telemetry. PhishGuard AI shall securely purge or anonymize all Customer data from active systems within 30 days of service decommissioning.
