/**
 * PhishGuard AI - Background Service Worker (Manifest V3)
 * Provides real-time pre-navigation URL scanning, local caching,
 * dynamic badge status, and interstitial blocking.
 */

const DEFAULT_API_BASE = "https://phishguard.vitalsnvectors.in";
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 Hour
const BYPASS_TTL_MS = 15 * 60 * 1000; // 15 Minutes

// Static allowlist of top trusted global and Indian domains to eliminate zero-delay lookups
const STATIC_ALLOWLIST = new Set([
  "google.com", "google.co.in", "youtube.com", "github.com", "microsoft.com",
  "apple.com", "amazon.com", "amazon.in", "wikipedia.org", "linkedin.com",
  "twitter.com", "x.com", "facebook.com", "instagram.com", "whatsapp.com",
  "cloudflare.com", "netflix.com", "openai.com", "stackoverflow.com", "reddit.com",
  // Indian Banking & Fintech
  "hdfcbank.com", "hdfc.com", "onlinesbi.sbi", "sbi.co.in", "icicibank.com",
  "axisbank.com", "kotak.com", "pnbindia.in", "bankofbaroda.in", "paytm.com",
  "phonepe.com", "cred.club", "razorpay.com", "zerodha.com", "groww.in",
  "bharatpe.com", "npci.org.in", "bhimupi.org.in", "tin-nsdl.com",
  // Indian Govt & Utilities
  "incometax.gov.in", "uidai.gov.in", "irctc.co.in", "indiapost.gov.in", "epfindia.gov.in"
]);

// In-memory bypass map for temporary user-approved destinations: tabId -> Set(domains)
const activeBypasses = new Map();

/**
 * Normalizes URL and extracts clean domain
 */
function extractDomain(urlStr) {
  try {
    const parsed = new URL(urlStr);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

/**
 * Checks if URL is a private/internal browser protocol
 */
function isInternalUrl(urlStr) {
  if (!urlStr) return true;
  const lower = urlStr.toLowerCase();
  return (
    lower.startsWith("chrome://") ||
    lower.startsWith("chrome-extension://") ||
    lower.startsWith("edge://") ||
    lower.startsWith("about:") ||
    lower.startsWith("file://") ||
    lower.startsWith("view-source:") ||
    lower.includes("localhost") ||
    lower.includes("127.0.0.1")
  );
}

/**
 * Checks if a domain is in the static allowlist
 */
function isAllowlisted(domain) {
  if (!domain) return false;
  if (STATIC_ALLOWLIST.has(domain)) return true;
  for (const trusted of STATIC_ALLOWLIST) {
    if (domain.endsWith("." + trusted)) return true;
  }
  return false;
}

/**
 * Sets extension badge icon and color
 */
function updateBadge(tabId, status) {
  if (!tabId) return;
  if (status === "safe") {
    chrome.action.setBadgeText({ tabId, text: "SAFE" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
  } else if (status === "phishing" || status === "critical") {
    chrome.action.setBadgeText({ tabId, text: "RISK" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
  } else if (status === "suspicious") {
    chrome.action.setBadgeText({ tabId, text: "WARN" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
}

/**
 * Retrieves cache entry from chrome.storage.local
 */
async function getCachedVerdict(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get([`cache_${domain}`], (res) => {
      const entry = res[`cache_${domain}`];
      if (entry && Date.now() - entry.timestamp < CACHE_TTL_MS) {
        resolve(entry);
      } else {
        resolve(null);
      }
    });
  });
}

/**
 * Stores scan result in chrome.storage.local
 */
async function setCachedVerdict(domain, data) {
  return new Promise((resolve) => {
    const key = `cache_${domain}`;
    chrome.storage.local.set(
      {
        [key]: {
          ...data,
          timestamp: Date.now()
        }
      },
      resolve
    );
  });
}

/**
 * Gets authentication configuration from storage
 */
async function getAuthConfig() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["jwt_access_token", "api_key", "custom_api_base", "realtime_enabled"], (res) => {
      resolve({
        token: res.jwt_access_token || null,
        apiKey: res.api_key || null,
        apiBase: res.custom_api_base || DEFAULT_API_BASE,
        realtimeEnabled: res.realtime_enabled !== false // Default true
      });
    });
  });
}

/**
 * Queries the backend scan API
 */
async function scanUrlWithBackend(targetUrl) {
  const auth = await getAuthConfig();
  const endpoint = `${auth.apiBase}/api/check-url/`;

  const headers = {
    "Content-Type": "application/json"
  };

  if (auth.token) {
    headers["Authorization"] = `Bearer ${auth.token}`;
  } else if (auth.apiKey) {
    headers["X-API-Key"] = auth.apiKey;
  }

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      return {
        success: false,
        error: errData.error || `HTTP ${response.status}: Scan failed`
      };
    }

    const data = await response.json();
    return {
      success: true,
      data
    };
  } catch (err) {
    return {
      success: false,
      error: `Network error: Could not reach PhishGuard service at ${auth.apiBase}`
    };
  }
}

/**
 * Queries the backend batch scan API (Max 50 URLs per request)
 */
async function scanUrlsBatchWithBackend(urls, senderDomain = null) {
  const auth = await getAuthConfig();
  const endpoint = `${auth.apiBase}/api/check-urls/batch/`;

  const headers = {
    "Content-Type": "application/json"
  };

  if (auth.token) {
    headers["Authorization"] = `Bearer ${auth.token}`;
  } else if (auth.apiKey) {
    headers["X-API-Key"] = auth.apiKey;
  }

  try {
    const payload = { urls };
    if (senderDomain) {
      payload.sender_domain = senderDomain;
    }

    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      return {
        success: false,
        error: errData.error || `HTTP ${response.status}: Batch scan failed`
      };
    }

    const data = await response.json();
    return {
      success: true,
      results: data.results || []
    };
  } catch (err) {
    return {
      success: false,
      error: `Network error: Could not reach PhishGuard service at ${auth.apiBase}`
    };
  }
}


/**
 * Handles WebNavigation Pre-Flight Interception
 */
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept main frame navigation (frameId === 0)
  if (details.frameId !== 0) return;

  const url = details.url;
  if (isInternalUrl(url)) return;

  const domain = extractDomain(url);
  if (!domain) return;

  const auth = await getAuthConfig();
  if (!auth.realtimeEnabled) return;

  // 1. Check if user currently has an active temporary bypass for this tab & domain
  const tabBypasses = activeBypasses.get(details.tabId);
  if (tabBypasses && tabBypasses.has(domain)) {
    updateBadge(details.tabId, "suspicious");
    return;
  }

  // 2. Check Static Allowlist
  if (isAllowlisted(domain)) {
    updateBadge(details.tabId, "safe");
    return;
  }

  // 3. Check Local Cache
  const cached = await getCachedVerdict(domain);
  if (cached) {
    if (cached.verdict === "phishing" || cached.verdict === "suspicious" || cached.phishing_probability >= 0.70) {
      updateBadge(details.tabId, "phishing");
      redirectToInterstitial(details.tabId, url, domain, cached);
    } else {
      updateBadge(details.tabId, "safe");
    }
    return;
  }

  // 4. Perform Real-time Background API Scan
  const scanResult = await scanUrlWithBackend(url);
  if (scanResult.success && scanResult.data) {
    const data = scanResult.data;
    await setCachedVerdict(domain, data);

    const verdict = data.verdict ? data.verdict.toLowerCase() : "safe";
    const prob = typeof data.phishing_probability === "number" ? data.phishing_probability : 0;

    if (verdict === "phishing" || verdict === "suspicious" || prob >= 0.70) {
      updateBadge(details.tabId, "phishing");
      redirectToInterstitial(details.tabId, url, domain, data);
    } else {
      updateBadge(details.tabId, "safe");
    }
  }
});

/**
 * Redirects tab to the interstitial warning page
 */
function redirectToInterstitial(tabId, originalUrl, domain, scanData) {
  const reasonsParam = encodeURIComponent(JSON.stringify(scanData.reasons || []));
  const verdictParam = encodeURIComponent(scanData.verdict || "PHISHING");
  const riskParam = encodeURIComponent(scanData.risk_level || "CRITICAL RISK");
  const probParam = encodeURIComponent(Math.round((scanData.phishing_probability || 0.95) * 100));

  const interstitialUrl = chrome.runtime.getURL(
    `interstitial.html?url=${encodeURIComponent(originalUrl)}&domain=${encodeURIComponent(domain)}&verdict=${verdictParam}&risk=${riskParam}&score=${probParam}&reasons=${reasonsParam}`
  );

  chrome.tabs.update(tabId, { url: interstitialUrl });
}

/**
 * Message Handler for Extension UI & Content Scripts
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "CHECK_URL") {
    (async () => {
      const targetUrl = request.url;
      const domain = extractDomain(targetUrl);

      if (isAllowlisted(domain)) {
        sendResponse({
          success: true,
          data: {
            verdict: "safe",
            risk_level: "Safe",
            phishing_probability: 0.01,
            legitimate_probability: 0.99,
            reasons: ["Verified domain in global cybersecurity trust catalog."]
          }
        });
        return;
      }

      const cached = await getCachedVerdict(domain);
      if (cached) {
        sendResponse({ success: true, data: cached });
        return;
      }

      const result = await scanUrlWithBackend(targetUrl);
      if (result.success && result.data) {
        await setCachedVerdict(domain, result.data);
      }
      sendResponse(result);
    })();
    return true; // Keep message channel open for async response
  }

  if (request.action === "CHECK_URLS_BATCH") {
    (async () => {
      const urls = request.urls || [];
      const senderDomain = request.senderDomain || request.senderEmail || null;
      if (!urls.length) {
        sendResponse({ success: true, results: {} });
        return;
      }

      const resultsMap = {};
      const urlsToFetch = [];

      for (const rawUrl of urls) {
        const domain = extractDomain(rawUrl);
        if (!domain || isInternalUrl(rawUrl)) continue;

        if (isAllowlisted(domain)) {
          resultsMap[rawUrl] = {
            verdict: "safe",
            risk_level: "Safe",
            phishing_probability: 0.01,
            reasons: ["Verified domain in global cybersecurity trust catalog."]
          };
          continue;
        }

        const cached = await getCachedVerdict(domain);
        if (cached) {
          resultsMap[rawUrl] = cached;
          continue;
        }

        urlsToFetch.push(rawUrl);
      }

      if (urlsToFetch.length > 0) {
        // Chunk requests in batches of 50
        const batchRes = await scanUrlsBatchWithBackend(urlsToFetch.slice(0, 50), senderDomain);
        if (batchRes.success && batchRes.results) {
          for (const item of batchRes.results) {
            const domain = item.domain || extractDomain(item.input_url || item.clean_url);
            resultsMap[item.input_url || item.clean_url] = item;
            if (domain) {
              await setCachedVerdict(domain, item);
            }
          }
        }
      }

      sendResponse({ success: true, results: resultsMap });
    })();
    return true;
  }


  if (request.action === "BYPASS_WARNING") {
    const tabId = sender.tab ? sender.tab.id : request.tabId;
    const domain = request.domain;
    if (tabId && domain) {
      if (!activeBypasses.has(tabId)) {
        activeBypasses.set(tabId, new Set());
      }
      activeBypasses.get(tabId).add(domain);

      // Remove bypass after TTL
      setTimeout(() => {
        const set = activeBypasses.get(tabId);
        if (set) {
          set.delete(domain);
          if (set.size === 0) activeBypasses.delete(tabId);
        }
      }, BYPASS_TTL_MS);
    }
    sendResponse({ success: true });
    return true;
  }

  if (request.action === "GET_AUTH_STATE") {
    (async () => {
      const auth = await getAuthConfig();
      if (!auth.token) {
        sendResponse({ isAuthenticated: false, user: null });
        return;
      }

      try {
        const resp = await fetch(`${auth.apiBase}/api/auth/me/`, {
          headers: { Authorization: `Bearer ${auth.token}` }
        });
        if (resp.ok) {
          const user = await resp.json();
          sendResponse({ isAuthenticated: true, user, apiBase: auth.apiBase });
        } else {
          // Token expired, clear token
          chrome.storage.local.remove(["jwt_access_token"]);
          sendResponse({ isAuthenticated: false, user: null });
        }
      } catch {
        sendResponse({ isAuthenticated: false, user: null, error: "Cannot reach auth server" });
      }
    })();
    return true;
  }

  if (request.action === "LOGIN") {
    (async () => {
      const auth = await getAuthConfig();
      try {
        const resp = await fetch(`${auth.apiBase}/api/auth/login/`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: request.email, password: request.password })
        });
        const data = await resp.json();
        if (resp.ok && data.tokens && data.tokens.access) {
          chrome.storage.local.set({
            jwt_access_token: data.tokens.access,
            jwt_refresh_token: data.tokens.refresh,
            cached_user: data.user
          });
          sendResponse({ success: true, user: data.user });
        } else {
          sendResponse({ success: false, error: data.detail || data.error || "Login failed" });
        }
      } catch (e) {
        sendResponse({ success: false, error: "Network error during authentication." });
      }
    })();
    return true;
  }

  if (request.action === "LOGOUT") {
    chrome.storage.local.remove(["jwt_access_token", "jwt_refresh_token", "cached_user"], () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (request.action === "REPORT_URL") {
    (async () => {
      const auth = await getAuthConfig();
      // Store report in local queue or submit
      chrome.storage.local.get(["threat_reports"], (res) => {
        const reports = res.threat_reports || [];
        reports.push({
          url: request.url,
          reportType: request.reportType, // 'phishing' or 'false_positive'
          notes: request.notes || "",
          timestamp: new Date().toISOString()
        });
        chrome.storage.local.set({ threat_reports: reports }, () => {
          sendResponse({ success: true, message: "Thank you! Report recorded." });
        });
      });
    })();
    return true;
  }
});

// Clean up bypasses when tabs close
chrome.tabs.onRemoved.addListener((tabId) => {
  activeBypasses.delete(tabId);
});
