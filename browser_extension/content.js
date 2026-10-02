/**
 * PhishGuard AI - Credential Protection Content Script
 * Scans page DOM for password/OTP fields, unverified forms, and cross-domain submissions.
 */

(function () {
  // Prevent double-injection
  if (window.__PHISHGUARD_CONTENT_INITIALIZED__) return;
  window.__PHISHGUARD_CONTENT_INITIALIZED__ = true;

  const currentHost = window.location.hostname.toLowerCase().replace(/^www\./, "");

  // Skip internal or chrome extension pages
  if (!currentHost || currentHost.includes("google.com") || currentHost.includes("localhost")) {
    return;
  }

  let bannerInjected = false;

  /**
   * Injects the floating credential warning banner
   */
  function showCredentialWarning(reasonText) {
    if (bannerInjected) return;
    bannerInjected = true;

    const banner = document.createElement("div");
    banner.id = "phishguard-credential-banner";
    banner.innerHTML = `
      <div class="phishguard-banner-inner">
        <div class="phishguard-banner-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <div class="phishguard-banner-content">
          <strong>PhishGuard AI Credential Warning:</strong>
          <span>${reasonText || "Verify domain before entering passwords, OTPs, or financial details."}</span>
        </div>
        <button id="phishguard-banner-close" class="phishguard-banner-close" aria-label="Dismiss">&times;</button>
      </div>
    `;

    document.documentElement.appendChild(banner);

    document.getElementById("phishguard-banner-close")?.addEventListener("click", () => {
      banner.remove();
    });
  }

  /**
   * Inspects sensitive input fields
   */
  function setupInputMonitoring() {
    const sensitiveSelectors = [
      'input[type="password"]',
      'input[name*="otp" i]',
      'input[name*="pin" i]',
      'input[name*="cvv" i]',
      'input[id*="otp" i]',
      'input[id*="password" i]'
    ];

    const fields = document.querySelectorAll(sensitiveSelectors.join(","));
    if (fields.length > 0) {
      // Query background worker for current domain classification
      chrome.runtime.sendMessage(
        { action: "CHECK_URL", url: window.location.href },
        (res) => {
          if (res && res.data) {
            const verdict = (res.data.verdict || "").toLowerCase();
            const prob = res.data.phishing_probability || 0;
            if (verdict === "phishing" || verdict === "suspicious" || prob >= 0.50) {
              showCredentialWarning(
                `High risk domain (${currentHost}). Do NOT enter bank PINs, OTPs, or credentials.`
              );
            }
          }
        }
      );
    }
  }

  /**
   * Inspects forms for cross-domain credential harvesting
   */
  function inspectForms() {
    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
      const action = form.getAttribute("action");
      if (action && action.startsWith("http")) {
        try {
          const actionHost = new URL(action).hostname.toLowerCase().replace(/^www\./, "");
          if (actionHost && actionHost !== currentHost && !actionHost.endsWith("." + currentHost)) {
            // Form posts to a different external host!
            form.addEventListener("submit", (e) => {
              const hasPassword = form.querySelector('input[type="password"]');
              if (hasPassword) {
                const confirmed = confirm(
                  `⚠️ PhishGuard Security Alert:\n\nThis form on '${currentHost}' submits your sensitive data to an EXTERNAL domain ('${actionHost}').\n\nThis is a common tactic in credential phishing scams.\n\nDo you want to cancel this submission?`
                );
                if (confirmed) {
                  e.preventDefault();
                  e.stopPropagation();
                }
              }
            });
          }
        } catch {
          // Invalid action URL
        }
      }
    });
  }

  // Run on load and after dynamic DOM shifts
  setupInputMonitoring();
  inspectForms();

  const observer = new MutationObserver(() => {
    setupInputMonitoring();
    inspectForms();
  });
  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });
})();
