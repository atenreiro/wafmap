<p align="center">
  <img src="images/wafprobe_logo.png" alt="wafprobe logo" width="300"/>
</p>

# 🦝 wafprobe

**wafprobe** is a lightweight, CLI-based tool designed to fingerprint Web Application Firewalls (WAFs), test signature coverage, analyze rate-limiting behavior, and detect edge-layer defenses.

> Know what your WAF blocks — and what it doesn’t.

---

## 🚀 Features

- 🔍 **WAF/CDN Fingerprinting** via response header analysis  
- 💥 **Signature-based payload testing** (SQLi, XSS, command injection)  
- ⚙️ **Rate-limit detection** (burst detection over sliding time windows)  
- 🎭 **User-Agent manipulation**, including random selection by OS/browser  
- 📦 Fully customizable via JSON config files  

---

## 📦 Installation

```bash
git clone https://github.com/atenreiro/wafprobe
cd wafprobe
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
