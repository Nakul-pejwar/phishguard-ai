/**
 * PhishGuard AI - Email Link Scanner (Gmail & Outlook Web)
 * Protects enterprise and consumer webmail in real-time by scanning links in opened emails,
 * detecting sender domain spoofing, and rendering inline threat warning badges.
 */

(function () {
  "use strict";

  const DEBOUNCE_DELAY_MS = 300;
  let scanTimeout = null;

  /**
   * Extracts email sender from active email header in DOM
   */
  function extractSenderAddress() {
    // 1. Gmail Selectors
    const gmailSenderElem = document.querySelector(".gD[email], span[email], .hP + span, [data-hovercard-id*='@']");
    if (gmailSenderElem) {
      return gmailSenderElem.getAttribute("email") || gmailSenderElem.getAttribute("data-hovercard-id") || gmailSenderElem.innerText;
    }

    // 2. Outlook Web Selectors
    const outlookSenderElem = document.querySelector(
      "[data-log-name='SenderIdentity'], [aria-label*='From:'], span[title*='@'], .allowTextSelection span[title*='@']"
    );
    if (outlookSenderElem) {
      const title = outlookSenderElem.getAttribute("title");
      if (title && title.includes("@")) return title;
      const text = outlookSenderElem.innerText;
      if (text && text.includes("@")) return text;
    }

    return null;
  }

  /**
   * Identifies if a URL should be skipped from threat scanning
   */
  function shouldSkipUrl(href) {
    if (!href) return true;
    const lower = href.toLowerCase().trim();
    if (
      lower.startsWith("javascript:") ||
      lower.startsWith("mailto:") ||
      lower.startsWith("tel:") ||
      lower.startsWith("#") ||
      lower.startsWith("about:") ||
      lower.startsWith("chrome-extension://")
    ) {
      return true;
    }

    try {
      const parsed = new URL(href);
      const host = parsed.hostname.toLowerCase();
      // Skip webmail core internal hosts
      if (
        host === "mail.google.com" ||
        host === "outlook.live.com" ||
        host === "outlook.office.com" ||
        host === "outlook.office365.com"
      ) {
        return true;
      }
    } catch {
      return true;
    }

    return false;
  }

  /**
   * Finds all email message body containers in Gmail & Outlook
   */
  function getEmailBodyContainers() {
    const containers = [];

    // Gmail email message containers
    const gmailBodies = document.querySelectorAll(".a3s.aiL, .adn.ads, div[role='main'] .ii.gt, .nH .hx");
    gmailBodies.forEach((el) => containers.push(el));

    // Outlook Web message containers
    const outlookBodies = document.querySelectorAll("[aria-label='Message body'], .customScrollBar div[role='document'], .ReadingPaneContainer");
    outlookBodies.forEach((el) => containers.push(el));

    return containers;
  }

  /**
   * Attaches inline security badge next to a scanned link
   */
  function renderThreatBadge(linkElem, result) {
    if (linkElem.dataset.phishguardChecked === "true") return;
    linkElem.dataset.phishguardChecked = "true";

    const isPhishing = result.verdict === "phishing" || result.risk_level === "Critical Risk" || result.risk_level === "high";
    const isSuspicious = result.verdict === "suspicious" || result.risk_level === "medium";

    const badge = document.createElement("span");
    badge.className = "phishguard-email-badge";

    if (isPhishing) {
      badge.classList.add("phishguard-badge-threat");
      badge.innerHTML = `🛡️ <strong>PHISHING RISK</strong>`;
      linkElem.classList.add("phishguard-flagged-threat");

      const tooltip = document.createElement("div");
      tooltip.className = "phishguard-tooltip";
      const reasonsList = (result.reasons || ["Flagged by PhishGuard AI Threat Engine"]).map(r => `<li>${r}</li>`).join("");
      tooltip.innerHTML = `
        <div class="phishguard-tooltip-header">⚠️ Warning: Dangerous Link Detected</div>
        <div class="phishguard-tooltip-body">
          <p><strong>Destination:</strong> ${result.domain || "Untrusted Domain"}</p>
          <ul>${reasonsList}</ul>
        </div>
      `;
      badge.appendChild(tooltip);

      // Warning intercept on click
      linkElem.addEventListener("click", (e) => {
        const proceed = window.confirm(
          `⚠️ PhishGuard Security Alert!\n\nThis link appears to be a phishing or spoofing attack:\n${linkElem.href}\n\nDo you really want to proceed at your own risk?`
        );
        if (!proceed) {
          e.preventDefault();
          e.stopPropagation();
        }
      }, true);

    } else if (isSuspicious) {
      badge.classList.add("phishguard-badge-warn");
      badge.innerHTML = `⚠️ <strong>CAUTION</strong>`;
      linkElem.classList.add("phishguard-flagged-warn");

      const tooltip = document.createElement("div");
      tooltip.className = "phishguard-tooltip";
      const reasonsList = (result.reasons || ["Suspicious domain characteristics"]).map(r => `<li>${r}</li>`).join("");
      tooltip.innerHTML = `
        <div class="phishguard-tooltip-header">Caution: Unverified Destination</div>
        <div class="phishguard-tooltip-body">
          <p><strong>Destination:</strong> ${result.domain || "Unverified Domain"}</p>
          <ul>${reasonsList}</ul>
        </div>
      `;
      badge.appendChild(tooltip);

    } else {
      badge.classList.add("phishguard-badge-safe");
      badge.innerHTML = `✓`;
      badge.title = "PhishGuard: Verified Safe Link";
      linkElem.classList.add("phishguard-flagged-safe");
    }

    // Insert badge right after the link
    if (linkElem.nextSibling) {
      linkElem.parentNode.insertBefore(badge, linkElem.nextSibling);
    } else {
      linkElem.parentNode.appendChild(badge);
    }
  }

  /**
   * Scans all unverified links within detected email bodies
   */
  function scanEmailLinks() {
    const containers = getEmailBodyContainers();
    if (!containers.length) return;

    const senderEmail = extractSenderAddress();
    const linksToScan = [];
    const urlLinkMap = new Map();

    containers.forEach((container) => {
      const anchorTags = container.querySelectorAll("a[href]");
      anchorTags.forEach((link) => {
        if (link.dataset.phishguardChecked === "true") return;

        const href = link.href;
        if (shouldSkipUrl(href)) {
          link.dataset.phishguardChecked = "true";
          return;
        }

        if (!urlLinkMap.has(href)) {
          urlLinkMap.set(href, []);
          linksToScan.push(href);
        }
        urlLinkMap.get(href).push(link);
      });
    });

    if (linksToScan.length === 0) return;

    // Send batch scan request to background worker
    chrome.runtime.sendMessage(
      {
        action: "CHECK_URLS_BATCH",
        urls: linksToScan,
        senderDomain: senderEmail
      },
      (response) => {
        if (!response || !response.success || !response.results) return;

        const results = response.results;
        for (const [url, linkElements] of urlLinkMap.entries()) {
          const scanResult = results[url] || { verdict: "safe", risk_level: "Safe", reasons: [] };
          linkElements.forEach((linkElem) => {
            renderThreatBadge(linkElem, scanResult);
          });
        }
      }
    );
  }

  /**
   * Debounced observer trigger
   */
  function scheduleScan() {
    if (scanTimeout) clearTimeout(scanTimeout);
    scanTimeout = setTimeout(scanEmailLinks, DEBOUNCE_DELAY_MS);
  }

  // Setup DOM MutationObserver to detect when emails are opened or navigated
  const observer = new MutationObserver(() => {
    scheduleScan();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Initial execution
  setTimeout(scheduleScan, 1000);
})();
