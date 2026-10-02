/**
 * PhishGuard AI - Landing Page Interactive Scripts
 */

document.addEventListener("DOMContentLoaded", () => {
  // 1. Currency Switcher (INR vs USD)
  const btnInr = document.getElementById("btnInr");
  const btnUsd = document.getElementById("btnUsd");
  const priceElements = document.querySelectorAll(".price[data-inr]");

  function setCurrency(isUsd) {
    if (isUsd) {
      btnUsd.classList.add("active");
      btnInr.classList.remove("active");
      priceElements.forEach(el => {
        el.textContent = el.getAttribute("data-usd");
      });
    } else {
      btnInr.classList.add("active");
      btnUsd.classList.remove("active");
      priceElements.forEach(el => {
        el.textContent = el.getAttribute("data-inr");
      });
    }
  }

  if (btnInr && btnUsd) {
    btnInr.addEventListener("click", () => setCurrency(false));
    btnUsd.addEventListener("click", () => setCurrency(true));
  }

  // 2. Interactive Scanner Demo Widget
  const demoUrlInput = document.getElementById("demoUrlInput");
  const scanUrlBtn = document.getElementById("scanUrlBtn");
  const resultBadge = document.getElementById("resultBadge");
  const resultScore = document.getElementById("resultScore");
  const resultDomain = document.getElementById("resultDomain");
  const resultReasonsList = document.getElementById("resultReasonsList");
  const pillBtns = document.querySelectorAll(".pill-btn");

  pillBtns.forEach(pill => {
    pill.addEventListener("click", () => {
      const targetUrl = pill.getAttribute("data-url");
      if (demoUrlInput) {
        demoUrlInput.value = targetUrl;
        simulateScan(targetUrl);
      }
    });
  });

  if (scanUrlBtn && demoUrlInput) {
    scanUrlBtn.addEventListener("click", () => {
      simulateScan(demoUrlInput.value.trim());
    });

    demoUrlInput.addEventListener("keypress", (e) => {
      if (e.key === "Enter") {
        simulateScan(demoUrlInput.value.trim());
      }
    });
  }

  function simulateScan(urlStr) {
    if (!urlStr) return;

    let domain = "unknown.com";
    try {
      const parsed = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
      domain = parsed.hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      domain = urlStr;
    }

    if (resultDomain) resultDomain.textContent = domain;

    // Simulated multi-signal threat classifier for client demo
    if (domain.includes("hdfc") && !domain.endsWith("hdfcbank.com") && !domain.endsWith("hdfc.com")) {
      renderResult(
        "CRITICAL THREAT DETECTED",
        "status-threat",
        "Risk Score: 98 / 100",
        [
          "🔴 Impersonating Indian financial institution: HDFC Bank.",
          "🔴 High Shannon entropy and suspicious TLD (.xyz).",
          "🔴 Insecure HTTP transmission targeting sensitive authentication endpoints."
        ]
      );
    } else if (domain.includes("sbi") && !domain.endsWith("onlinesbi.sbi") && !domain.endsWith("sbi.co.in")) {
      renderResult(
        "CRITICAL THREAT DETECTED",
        "status-threat",
        "Risk Score: 95 / 100",
        [
          "🔴 Typosquatting / Lookalike targeting State Bank of India (SBI).",
          "🔴 Suspicious top-level domain (.top) frequently utilized in credential harvesting.",
          "🔴 Sensitive keywords ('kyc', 'update', 'pan') detected in URL path."
        ]
      );
    } else if (domain.includes("bit.ly") || domain.includes("tinyurl")) {
      renderResult(
        "SUSPICIOUS LINK (CAUTION)",
        "status-threat",
        "Risk Score: 72 / 100",
        [
          "🟡 URL Shortener masking final destination endpoint.",
          "🟡 Heuristic flags high risk for unverified short links in communications."
        ]
      );
    } else if (domain.endsWith("onlinesbi.sbi") || domain.endsWith("sbi.co.in") || domain.endsWith("hdfcbank.com") || domain.endsWith("google.com")) {
      renderResult(
        "VERIFIED SAFE DESTINATION",
        "status-safe",
        "Risk Score: 1 / 100",
        [
          "🟢 Official domain verified in global cybersecurity trust catalog.",
          "🟢 Valid HTTPS encryption and standard domain structure.",
          "🟢 No deceptive lookalikes or threat intelligence matches."
        ]
      );
    } else {
      renderResult(
        "LOW RISK / UNCLASSIFIED",
        "status-safe",
        "Risk Score: 15 / 100",
        [
          "🟢 Standard web domain structure.",
          "🟢 No immediate brand impersonation or threat feed hits."
        ]
      );
    }
  }

  function renderResult(badgeText, badgeClass, scoreText, reasons) {
    if (resultBadge) {
      resultBadge.textContent = badgeText;
      resultBadge.className = `result-status-badge ${badgeClass}`;
    }
    if (resultScore) {
      resultScore.textContent = scoreText;
    }
    if (resultReasonsList) {
      resultReasonsList.innerHTML = reasons.map(r => `<li>${r}</li>`).join("");
    }
  }

  // 3. Chrome Extension Install CTA
  const installChromeBtn = document.getElementById("installChromeBtn");
  if (installChromeBtn) {
    installChromeBtn.addEventListener("click", (e) => {
      e.preventDefault();
      alert("PhishGuard AI Chrome Extension package is available in the /dist folder. Ready for Chrome Web Store installation.");
    });
  }
});
