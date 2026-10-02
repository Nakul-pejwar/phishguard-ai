/**
 * PhishGuard AI - Interstitial Warning Controller
 * Handles parsing threat telemetry, user return, bypass overrides, and false-positive reporting.
 */

document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const targetUrl = params.get("url") || "Unknown Destination";
  const domain = params.get("domain") || "Unknown Domain";
  const verdict = params.get("verdict") || "PHISHING DETECTED";
  const risk = params.get("risk") || "CRITICAL RISK";
  const score = parseInt(params.get("score") || "95", 10);
  let reasons = [];

  try {
    reasons = JSON.parse(params.get("reasons") || "[]");
  } catch {
    reasons = ["Suspicious domain characteristics matching phishing heuristics."];
  }

  // Populate UI elements
  document.getElementById("targetDomain").textContent = domain;
  document.getElementById("targetVerdict").textContent = verdict.toUpperCase();
  document.getElementById("threatScore").textContent = `${score}%`;
  document.getElementById("meterFill").style.width = `${Math.min(100, Math.max(10, score))}%`;
  document.getElementById("fullUrl").textContent = targetUrl;

  const reasonsListEl = document.getElementById("reasonsList");
  reasonsListEl.innerHTML = "";
  if (reasons.length === 0) {
    reasons = ["Suspicious domain structure and lexical characteristics."];
  }
  reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    reasonsListEl.appendChild(li);
  });

  // Action: Return to Safety
  document.getElementById("goBackBtn").addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = "https://www.google.com";
    }
  });

  // Action: Proceed Anyway (Bypass)
  document.getElementById("proceedAnywayBtn").addEventListener("click", () => {
    const confirmProceed = confirm(
      "⚠️ WARNING: This website has been flagged as dangerous.\n\nContinuing may compromise your banking credentials, passwords, or personal data.\n\nAre you sure you want to proceed?"
    );
    if (confirmProceed && targetUrl.startsWith("http")) {
      chrome.runtime.sendMessage(
        { action: "BYPASS_WARNING", domain },
        () => {
          window.location.href = targetUrl;
        }
      );
    }
  });

  // Action: Report False Positive
  document.getElementById("reportFalsePositiveBtn").addEventListener("click", () => {
    const reportBtn = document.getElementById("reportFalsePositiveBtn");
    reportBtn.disabled = true;
    reportBtn.textContent = "Reporting...";

    chrome.runtime.sendMessage(
      {
        action: "REPORT_URL",
        url: targetUrl,
        reportType: "false_positive",
        notes: "Reported directly from interstitial warning screen."
      },
      (res) => {
        reportBtn.textContent = "✓ Reported to Security Team";
        reportBtn.style.color = "#10B981";
      }
    );
  });
});
