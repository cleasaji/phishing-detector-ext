"""
Phishing URL Classifier — Naive Bayes training script
Uses URL-based features only (no external API calls needed)
"""

import re
import json
from urllib.parse import urlparse

# ── Feature extraction ──────────────────────────────────────────────────────

def extract_features(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        fullurl  = url.lower()

        features = {
            "url_length":          len(url),
            "hostname_length":     len(hostname),
            "num_dots":            hostname.count("."),
            "num_hyphens":         hostname.count("-"),
            "num_subdomains":      len(hostname.split(".")) - 2,
            "has_ip":              int(bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))),
            "has_at_symbol":       int("@" in url),
            "has_https":           int(parsed.scheme == "https"),
            "path_depth":          path.count("/"),
            "has_login_keyword":   int(any(k in fullurl for k in ["login","signin","verify","update","secure","account","password"])),
            "has_phish_keyword":   int(any(k in fullurl for k in ["phish","malware","hack","steal","fake"])),
            "num_special_chars":   sum(url.count(c) for c in ["%", "=", "?", "&"]),
            "suspicious_tld":      int(any(hostname.endswith(t) for t in [".tk",".ml",".ga",".cf",".gq"])),
        }
        return list(features.values())
    except Exception:
        return [0] * 13


# ── Sample dataset (in production, load from PhishTank CSV) ─────────────────

SAMPLE_DATA = [
    # (url, label)  1 = phishing, 0 = legitimate
    ("https://www.google.com", 0),
    ("https://github.com/login", 0),
    ("https://www.amazon.com/dp/B08N5KWB9H", 0),
    ("http://192.168.1.1/login", 1),
    ("http://secure-verify-account.tk/login?user=admin", 1),
    ("http://paypal.com.verify-identity.net/signin", 1),
    ("https://stackoverflow.com/questions/12345", 0),
    ("http://update-payment-now.ga/account", 1),
    ("http://fake-bank-login.ml/secure/verify", 1),
    ("https://microsoft.com/en-us/microsoft-365", 0),
]


def train_naive_bayes(data):
    """Minimal Naive Bayes without sklearn for demonstration"""
    phish   = [extract_features(u) for u, l in data if l == 1]
    legit   = [extract_features(u) for u, l in data if l == 0]

    def mean(vals):
        return sum(vals) / len(vals) if vals else 0

    n_features = len(phish[0])
    model = {
        "prior_phish": len(phish) / len(data),
        "prior_legit":  len(legit) / len(data),
        "phish_means":  [mean([p[i] for p in phish]) for i in range(n_features)],
        "legit_means":  [mean([p[i] for p in legit]) for i in range(n_features)],
    }
    return model


def predict(model, url):
    features = extract_features(url)
    phish_score = model["prior_phish"]
    legit_score  = model["prior_legit"]

    for i, f in enumerate(features):
        phish_score *= max(abs(f - model["phish_means"][i]) + 0.1, 0.1)
        legit_score  *= max(abs(f - model["legit_means"][i]) + 0.1, 0.1)

    return "PHISHING" if phish_score > legit_score else "SAFE"


if __name__ == "__main__":
    print("[*] Training Naive Bayes classifier on sample data...")
    model = train_naive_bayes(SAMPLE_DATA)

    with open("model.json", "w") as f:
        json.dump(model, f, indent=2)
    print("[+] Model saved to model.json")

    print("\n[*] Testing on sample URLs:")
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login",
        "http://secure-verify-account.tk/login",
        "https://github.com",
        "http://paypal.com.verify.net/signin",
    ]
    for url in test_urls:
        label = predict(model, url)
        print(f"  {label:10} — {url}")
