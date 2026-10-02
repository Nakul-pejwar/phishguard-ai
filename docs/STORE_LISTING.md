# PhishGuard AI - Chrome Web Store & Edge Add-ons Listing Kit

This document contains all production metadata, store copy, promotional text, permission justifications, and reviewer instructions required for publishing **PhishGuard AI** on the **Chrome Web Store**, **Microsoft Edge Add-ons**, and **Mozilla Add-ons (AMO)**.

---

## 1. Store Metadata & Basic Info

| Field | Content |
| :--- | :--- |
| **Product Name** | PhishGuard AI — Real-Time Phishing & Spoof Protection |
| **Short Name** | PhishGuard AI |
| **Category** | Productivity / Security & Privacy / Developer Tools |
| **Language** | English (Global), English (India) |
| **Price / Model** | Free with Pro & Enterprise subscription tiers |
| **Support Email** | support@phishguard.ai / security@phishguard.ai |
| **Privacy Policy URL** | `https://phishguard.ai/privacy-policy` |
| **Terms of Service URL** | `https://phishguard.ai/terms` |
| **Homepage URL** | `https://phishguard.ai` |

---

## 2. Short Description (Max 132 chars)
> **AI-powered real-time phishing defense, BFSI lookalike detection, credential theft prevention, and email link scanner with zero PII.**

---

## 3. Detailed Store Description (Formatted for Chrome Web Store & Edge)

```markdown
🛡️ PhishGuard AI: Real-Time Zero-PII Phishing & Credential Guard

PhishGuard AI protects individuals, fintechs, banks, and enterprises from advanced phishing attacks, brand impersonation, zero-day credential harvesting, and deceptive email links. Powered by a multi-signal AI engine with sub-100ms threat verdict latency.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔥 WHY PHISHGUARD AI?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Standard blocklists miss newly registered zero-day phishing domains. PhishGuard AI combines on-device heuristics with cloud-based machine learning, Shannon entropy evaluation, visual/lexical typosquat analysis, and domain age verification to detect threats before they appear on global threat feeds.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✨ CORE CAPABILITIES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. ⚡ Pre-Navigation Interception
   Catches malicious redirects and malicious phishing links *before* the destination page loads, halting credential harvesting attempts in their tracks.

2. 🏦 Specialized Indian BFSI & Global Brand Protection
   Advanced typosquatting and homograph attack detection for 40+ top Indian banks, fintechs, UPI portals, and government utilities (SBI, HDFC, ICICI, Zerodha, Paytm, Income Tax, EPFO, and global brands like Google, Microsoft, PayPal).

3. 📧 In-Inbox Email Scanner (Gmail & Outlook Web)
   Automatically evaluates embedded links inside emails, detects sender-domain vs. link-domain spoofing mismatches, and overlays security badges directly in your email view.

4. 🛡️ Deceptive Credential Form Defense
   Detects password, OTP, and banking PIN input fields hosted on suspicious or high-entropy domains and raises an instant warning banner.

5. 🔒 Zero-PII by Design
   PhishGuard AI never captures, logs, or transmits personal data, form values, passwords, or browsing histories. Only cryptographic domain hashes (SHA-256) and threat features are processed. Compliant with the India DPDP Act 2023 and GDPR.

6. 🏢 Enterprise-Ready (Pro / Team / Enterprise Plans)
   • Centralized Team Dashboard with live attack analytics
   • Custom allow/block policies
   • SAML 2.0 / OIDC Single Sign-On (Okta, Azure AD / Entra ID, Google Workspace)
   • Real-time SIEM streaming (Splunk HEC, Microsoft Sentinel, Datadog)
   • Immutable audit logs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚙️ HOW IT WORKS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Install the extension.
2. Browse securely. When PhishGuard detects a high-risk phishing destination, an interstitial warning appears with the threat breakdown.
3. (Optional) Connect your API Key or Enterprise SSO in the extension popup for team-level telemetry and customized risk policies.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 PRIVACY & SECURITY COMMITMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Zero credential or keystroke logging
• Zero selling of browsing history or behavioral telemetry
• End-to-end TLS 1.3 encryption
• Strict automated retention and Right-to-Erasure compliance
```

---

## 4. Single-Purpose & Permission Justification (For Chrome Reviewers)

### Single-Purpose Statement
> *PhishGuard AI protects users from web-based phishing, credential theft, and brand spoofing by intercepting navigation to malicious domains and analyzing email links in real time.*

### Permission Justifications

| Permission | Technical Requirement & Justification |
| :--- | :--- |
| `webNavigation` | **Required** to intercept outgoing navigation requests (`onBeforeNavigate`) before HTML rendering occurs, checking destination URLs against the zero-latency local cache and multi-signal backend to prevent drive-by credential harvesting. |
| `storage` | **Required** to cache recent threat verdicts locally (TTL 300s) to minimize redundant network calls, and store user preferences / API authorization keys securely in `chrome.storage.local`. |
| `activeTab` | **Required** to display threat verdict overlays, credential warning banners, and interstitial security prompts on the current active tab when a risk is detected. |
| `alarms` | **Required** to trigger periodic background cache purges and threat feed rule refreshes without keeping a persistent background thread alive (Manifest V3 compliance). |
| `notifications` | **Required** to alert the user when an active page attempts to submit credentials to a deceptive or newly registered malicious domain. |
| Host Permissions (`*://*/*`) | **Required** to scan pre-navigation URLs across the open web and inject warning banners on detected malicious websites. |
| Host Permissions (`*://mail.google.com/*`, `*://outlook.live.com/*`, `*://outlook.office.com/*`) | **Required** for the email scanner content script (`email_scanner.js`) to parse incoming email link elements and flag spoofed sender domains directly in the webmail interface. |

---

## 5. Reviewer Notes & Test Credentials

```text
Dear Chrome / Edge / AMO Extension Review Team,

Thank you for reviewing PhishGuard AI.

To test the extension's full functionality:
1. Load the unpacked extension or install the submission package.
2. Open the extension popup:
   - Default mode runs against our public cloud engine.
   - Status will show "PhishGuard Active (Protected)".
3. Test Phishing Interception:
   - Navigate to test simulation: https://testsafebrowsing.appspot.com/s/phishing.html or http://sbi-login-verify-update.fakebank.in/
   - PhishGuard AI will intercept the tab before loading and redirect to the built-in warning interstitial (warning.html).
4. Test Webmail Scanner:
   - Open Gmail (https://mail.google.com) or Outlook Web.
   - Any email containing links will be annotated with a secure/warning badge based on link reputation.
5. Enterprise / Pro Mode (Optional):
   - In popup.html, click "Settings" and enter Test API Key: "pg_live_test_reviewer_key_2026"

Privacy Compliance:
- PhishGuard AI logs zero PII. Only SHA-256 hashes of domains and threat classification metrics are transmitted.
- Complete privacy policy is accessible at: https://phishguard.ai/privacy-policy

Please contact security@phishguard.ai if you require additional verification environments or backend access.
```

---

## 6. Promotional Asset Specifications

- **Small Promo Tile**: 440 x 280 px (PNG/WebP) - Clean PhishGuard shield with "Real-Time AI Phishing Shield" tagline.
- **Large Promo Tile**: 920 x 680 px (PNG/WebP) - Dashboard view + Interstitial Warning screen mockup.
- **Marquee Promo Tile**: 1400 x 560 px (PNG/WebP) - Enterprise BFSI & In-Inbox Email Scanner illustration.
- **Screenshots (1280 x 800 px)**:
  1. *Screenshot 1*: Pre-navigation Interstitial Warning Page (Blocked malicious BFSI replica).
  2. *Screenshot 2*: Gmail / Outlook In-Inbox Link Spoofing Badges.
  3. *Screenshot 3*: Quick-action Extension Popup with Risk Score breakdown.
  4. *Screenshot 4*: Credential Theft Warning Banner on deceptive login form.
  5. *Screenshot 5*: Enterprise Security Operations Center (SOC) Live Threat Feed & Analytics.
