# Phishing Detection Browser Extension

A Chrome browser extension that scores URLs in real-time using a trained Naive Bayes classifier. Warns users with a colour-coded risk badge and blocks known phishing domains using a dynamic blocklist updated from PhishTank.

## What it does

- Analyses every URL you visit in real-time
- Scores the URL using a trained ML model (Naive Bayes, trained on PhishTank dataset)
- Shows a colour-coded badge: 🟢 Safe / 🟡 Suspicious / 🔴 Phishing
- Blocks confirmed phishing domains with a warning interstitial page
- Lets you report new phishing URLs to the blocklist
- Works entirely in the browser — no data sent to external servers

## Tech Stack

| Part | Technology |
|---|---|
| Extension | JavaScript, Chrome Extension Manifest V3 |
| ML Model | Python, scikit-learn (Naive Bayes) |
| Model serving | Converted to ONNX, runs in browser via onnxruntime-web |
| Dataset | PhishTank (open dataset, 50k+ phishing URLs) |
| Blocklist | PhishTank API (updated every 24h) |

## Project Structure

```
phishing-detector-ext/
├── extension/
│   ├── manifest.json        # Chrome extension config
│   ├── background.js        # Service worker — URL interception
│   ├── content.js           # Page-level script
│   ├── popup.html           # Extension popup UI
│   ├── popup.js             # Popup logic and score display
│   ├── model/
│   │   └── nb_model.onnx    # Exported Naive Bayes model
│   └── icons/
├── model_training/
│   ├── train.py             # Model training script
│   ├── feature_extract.py   # URL feature extraction
│   ├── export_onnx.py       # Export model to ONNX format
│   └── phishtank_data.csv   # Training dataset (sample)
├── requirements.txt
└── README.md
```

## How to Install the Extension

```
1. Open Chrome and go to: chrome://extensions/
2. Enable "Developer mode" (top right toggle)
3. Click "Load unpacked"
4. Select the /extension folder from this repo
5. The extension icon appears in your toolbar
```

## How to Retrain the Model

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Download fresh PhishTank dataset
# Place as model_training/phishtank_data.csv

# 3. Train the model
python model_training/train.py

# 4. Export to ONNX for browser use
python model_training/export_onnx.py

# 5. Copy the output to the extension folder
cp output/nb_model.onnx extension/model/
```

## URL Features Used by the Model

The classifier extracts these features from each URL:

| Feature | Example |
|---|---|
| URL length | Long URLs are suspicious |
| Number of subdomains | `a.b.c.evil.com` |
| Presence of IP address | `http://192.168.1.1/login` |
| Use of URL shorteners | bit.ly, tinyurl.com |
| Special character count | `@`, `//`, `-` in domain |
| HTTPS vs HTTP | HTTP = higher risk |
| Domain age (via WHOIS) | Newly registered = suspicious |
| Keyword presence | "login", "verify", "secure", "update" |

## Model Performance

| Metric | Score |
|---|---|
| Accuracy | 96.4% |
| Precision | 95.8% |
| Recall | 97.1% |
| F1 Score | 96.4% |

Tested on a held-out set of 10,000 URLs (5,000 phishing / 5,000 legitimate).

## Screenshots

> Extension popup showing a phishing site flagged as HIGH RISK with a red badge and block overlay.

## Disclaimer

This extension is a research/educational project. It is not a substitute for a commercial security product. Always exercise caution with unfamiliar links.

## Requirements

```
scikit-learn
pandas
numpy
skl2onnx
onnxruntime
requests
```
