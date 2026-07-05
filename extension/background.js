// Phishing Detection Extension — Background Service Worker

const PHISHING_KEYWORDS = [
  "verify-account", "secure-login", "update-payment", "confirm-identity",
  "account-suspended", "unusual-activity", "reset-password-now", "signin-verify"
];

const SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq"];

const BLOCKLIST = new Set([
  "phishing-example.com",
  "fake-bank-login.net",
  "stealmypassword.tk"
]);

function scoreURL(url) {
  let score = 0;
  const reasons = [];

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();

    // Check blocklist
    if (BLOCKLIST.has(hostname)) {
      return { score: 100, label: "PHISHING", reasons: ["Domain is on phishing blocklist"] };
    }

    // IP address instead of domain
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      score += 40;
      reasons.push("IP address used instead of domain name");
    }

    // Suspicious TLD
    for (const tld of SUSPICIOUS_TLDS) {
      if (hostname.endsWith(tld)) {
        score += 25;
        reasons.push(`Suspicious TLD: ${tld}`);
      }
    }

    // Too many subdomains
    const subdomains = hostname.split(".").length - 2;
    if (subdomains >= 3) {
      score += 20;
      reasons.push(`Excessive subdomains (${subdomains})`);
    }

    // Phishing keywords in URL
    for (const kw of PHISHING_KEYWORDS) {
      if (fullUrl.includes(kw)) {
        score += 20;
        reasons.push(`Suspicious keyword: "${kw}"`);
      }
    }

    // Very long URL
    if (url.length > 200) {
      score += 10;
      reasons.push("Unusually long URL");
    }

    // @ symbol in URL (credential phishing trick)
    if (fullUrl.includes("@")) {
      score += 30;
      reasons.push("@ symbol in URL (credential theft technique)");
    }

    // HTTP (not HTTPS)
    if (parsed.protocol === "http:") {
      score += 10;
      reasons.push("Not using HTTPS");
    }

  } catch (e) {
    return { score: 0, label: "SAFE", reasons: [] };
  }

  let label = "SAFE";
  if (score >= 60) label = "PHISHING";
  else if (score >= 30) label = "SUSPICIOUS";

  return { score: Math.min(score, 100), label, reasons };
}

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    const result = scoreURL(tab.url);

    // Set badge color and text
    const colors = { PHISHING: "#dc2626", SUSPICIOUS: "#f59e0b", SAFE: "#16a34a" };
    const labels = { PHISHING: "!", SUSPICIOUS: "?", SAFE: "✓" };

    chrome.action.setBadgeBackgroundColor({ color: colors[result.label], tabId });
    chrome.action.setBadgeText({ text: labels[result.label], tabId });

    // Store result for popup
    chrome.storage.session.set({ [`result_${tabId}`]: result });
  }
});

// Message handler for popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_SCORE") {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id;
      chrome.storage.session.get([`result_${tabId}`], (data) => {
        sendResponse(data[`result_${tabId}`] || { score: 0, label: "SAFE", reasons: [] });
      });
    });
    return true;
  }
});
