/* ═══════════════════════════════════════════
   PHISHGUARD AI — POPUP CONTROLLER v2
   ═══════════════════════════════════════════ */

document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  const currentUrlEl = document.getElementById("currentUrl");
  const scanBtn = document.getElementById("scanBtn");
  const manualUrlInput = document.getElementById("manualUrlInput");
  const manualScanBtn = document.getElementById("manualScanBtn");

  const resultCard = document.getElementById("resultCard");
  const verdictText = document.getElementById("verdictText");
  const riskText = document.getElementById("riskText");
  const scoreText = document.getElementById("scoreText");
  const scoreBar = document.getElementById("scoreBar");
  const domainText = document.getElementById("domainText");
  const reasonsBox = document.getElementById("reasonsBox");
  const planBadgeHeader = document.getElementById("planBadgeHeader");
  const reportPhishingBtn = document.getElementById("reportPhishingBtn");

  const errorText = document.getElementById("errorText");
  const errorMsg = document.getElementById("errorMsg");

  // Account Elements
  const accountLoggedIn = document.getElementById("accountLoggedIn");
  const accountLoggedOut = document.getElementById("accountLoggedOut");
  const userName = document.getElementById("userName");
  const userEmail = document.getElementById("userEmail");
  const userPlanBadge = document.getElementById("userPlanBadge");
  const userAvatar = document.getElementById("userAvatar");
  const quotaText = document.getElementById("quotaText");
  const quotaFill = document.getElementById("quotaFill");
  const loginForm = document.getElementById("loginForm");
  const loginEmail = document.getElementById("loginEmail");
  const loginPassword = document.getElementById("loginPassword");
  const loginError = document.getElementById("loginError");
  const logoutBtn = document.getElementById("logoutBtn");

  // Settings Elements
  const toggleRealtime = document.getElementById("toggleRealtime");
  const toggleCredentials = document.getElementById("toggleCredentials");
  const customApiBase = document.getElementById("customApiBase");
  const saveSettingsBtn = document.getElementById("saveSettingsBtn");

  let activeTabUrl = "";

  // 1. Tab Switching
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      tabContents.forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");
    });
  });

  // 2. Load Settings & Auth State
  chrome.storage.local.get(
    ["realtime_enabled", "credentials_enabled", "custom_api_base"],
    (res) => {
      toggleRealtime.checked = res.realtime_enabled !== false;
      toggleCredentials.checked = res.credentials_enabled !== false;
      if (res.custom_api_base) {
        customApiBase.value = res.custom_api_base;
      }
    }
  );

  saveSettingsBtn.addEventListener("click", () => {
    chrome.storage.local.set({
      custom_api_base: customApiBase.value.trim()
    }, () => {
      alert("Settings saved successfully.");
    });
  });

  toggleRealtime.addEventListener("change", (e) => {
    chrome.storage.local.set({ realtime_enabled: e.target.checked });
  });

  toggleCredentials.addEventListener("change", (e) => {
    chrome.storage.local.set({ credentials_enabled: e.target.checked });
  });

  // 3. Check Auth State
  function refreshAuthState() {
    chrome.runtime.sendMessage({ action: "GET_AUTH_STATE" }, (res) => {
      if (res && res.isAuthenticated && res.user) {
        accountLoggedIn.classList.remove("hidden");
        accountLoggedOut.classList.add("hidden");

        const u = res.user;
        userName.textContent = `${u.first_name || ""} ${u.last_name || ""}`.trim() || u.email;
        userEmail.textContent = u.email;
        userAvatar.textContent = (u.first_name ? u.first_name[0] : u.email[0]).toUpperCase();

        const planName = (u.organization && u.organization.plan) ? u.organization.plan.name : "Free";
        userPlanBadge.textContent = `${planName} Plan`;
        planBadgeHeader.textContent = planName.toUpperCase();

        // Update Quota display
        const maxDaily = planName.toLowerCase().includes("pro") ? 500 : 20;
        const used = u.scans_today || 1;
        quotaText.textContent = `${used} / ${maxDaily} used`;
        quotaFill.style.width = `${Math.min(100, Math.round((used / maxDaily) * 100))}%`;
      } else {
        accountLoggedIn.classList.add("hidden");
        accountLoggedOut.classList.remove("hidden");
        planBadgeHeader.textContent = "FREE TRIAL";
      }
    });
  }
  refreshAuthState();

  // 4. Handle Login Form
  loginForm.addEventListener("submit", (e) => {
    e.preventDefault();
    loginError.classList.add("hidden");

    chrome.runtime.sendMessage(
      {
        action: "LOGIN",
        email: loginEmail.value.trim(),
        password: loginPassword.value
      },
      (res) => {
        if (res && res.success) {
          refreshAuthState();
          document.getElementById("tabShield").click();
        } else {
          loginError.textContent = (res && res.error) || "Invalid credentials.";
          loginError.classList.remove("hidden");
        }
      }
    );
  });

  // 5. Handle Logout
  logoutBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "LOGOUT" }, () => {
      refreshAuthState();
    });
  });

  // 6. Inspect Active Browser Tab
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      activeTabUrl = tabs[0].url;
      currentUrlEl.textContent = activeTabUrl;

      // Auto-scan active tab
      if (activeTabUrl.startsWith("http")) {
        performScan(activeTabUrl);
      } else {
        currentUrlEl.textContent = "Internal browser page (Safe)";
      }
    } else {
      currentUrlEl.textContent = "No active page detected";
    }
  });

  // 7. Manual & Quick Scan Triggers
  scanBtn.addEventListener("click", () => {
    if (activeTabUrl && activeTabUrl.startsWith("http")) {
      performScan(activeTabUrl);
    }
  });

  manualScanBtn.addEventListener("click", () => {
    const customUrl = manualUrlInput.value.trim();
    if (customUrl) {
      performScan(customUrl);
    }
  });

  // 8. Core Scan Routine
  function performScan(urlToScan) {
    errorText.classList.add("hidden");
    scanBtn.disabled = true;
    scanBtn.querySelector(".btn-text").textContent = "SCANNING...";

    chrome.runtime.sendMessage(
      { action: "CHECK_URL", url: urlToScan },
      (response) => {
        scanBtn.disabled = false;
        scanBtn.querySelector(".btn-text").textContent = "SCAN ACTIVE PAGE";

        if (!response || !response.success || !response.data) {
          showError((response && response.error) || "Scan failed. Please check network connection.");
          return;
        }

        renderResult(response.data);
      }
    );
  }

  function renderResult(data) {
    resultCard.classList.remove("hidden", "safe", "phishing", "suspicious");

    const verdict = (data.verdict || "SAFE").toUpperCase();
    const prob = typeof data.phishing_probability === "number" ? data.phishing_probability : 0;
    const pct = Math.round(prob * 100);

    verdictText.textContent = verdict;
    riskText.textContent = data.risk_level || "Analysis Complete";
    scoreText.textContent = `${pct}%`;
    scoreBar.style.width = `${Math.max(5, pct)}%`;
    domainText.textContent = data.domain || "-";

    if (verdict.includes("PHISH") || pct >= 70) {
      resultCard.classList.add("phishing");
    } else if (verdict.includes("SUSPIC") || pct >= 40) {
      resultCard.classList.add("suspicious");
    } else {
      resultCard.classList.add("safe");
    }

    reasonsBox.innerHTML = "";
    const reasons = data.reasons || ["Lexical and threat intelligence checks passed."];
    reasons.forEach((r) => {
      const item = document.createElement("div");
      item.textContent = `• ${r}`;
      reasonsBox.appendChild(item);
    });
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorText.classList.remove("hidden");
  }

  // 9. Report False Positive / Phishing Link
  reportPhishingBtn.addEventListener("click", () => {
    if (!activeTabUrl) return;
    chrome.runtime.sendMessage(
      {
        action: "REPORT_URL",
        url: activeTabUrl,
        reportType: "false_positive",
        notes: "Reported from popup card."
      },
      (res) => {
        reportPhishingBtn.textContent = "✓ Report Submitted to Security Team";
        reportPhishingBtn.style.color = "#10b981";
      }
    );
  });

  // 10. Neural Background Canvas
  initNeuralCanvas();
});

function initNeuralCanvas() {
  const canvas = document.getElementById("neuralCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  let width = (canvas.width = 380);
  let height = (canvas.height = 540);

  const nodes = [];
  for (let i = 0; i < 24; i++) {
    nodes.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.4,
      vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 2 + 1
    });
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // Draw connections
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const dx = nodes[i].x - nodes[j].x;
        const dy = nodes[i].y - nodes[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 90) {
          ctx.strokeStyle = `rgba(0, 212, 255, ${0.15 * (1 - dist / 90)})`;
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();
        }
      }
    }

    // Draw nodes
    for (const n of nodes) {
      n.x += n.vx;
      n.y += n.vy;
      if (n.x < 0 || n.x > width) n.vx *= -1;
      if (n.y < 0 || n.y > height) n.vy *= -1;

      ctx.fillStyle = "rgba(0, 212, 255, 0.4)";
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    requestAnimationFrame(draw);
  }
  draw();
}
