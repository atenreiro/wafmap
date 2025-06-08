# WAFMap

**WAFMap** is a command line tool for mapping web application firewalls and
testing for signature or rate‑limit gaps. It fingerprints WAF/CDN vendors,
runs common attack payloads to gauge coverage and can probe additional defenses
such as HTTP/2 or JA4 TLS fingerprints.

> Know what your WAF blocks — and what it doesn’t.

---

## Features

- **WAF/CDN discovery** via HTTP header heuristics
- **Signature testing** using YAML based payload libraries
- **Rate‑limit detection** with adjustable request rates
- **JA4 TLS and HTTP/2 fingerprinting**
- **Custom User‑Agent support** including random selection

---

## Installation

```bash
git clone https://github.com/atenreiro/wafmap
cd wafmap
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## Usage

Discover WAF/CDN vendors:

```bash
wafmap discover https://example.com
```

Run signature gap tests and show HTTP codes:

```bash
wafmap test https://example.com --verbose
```

Check for rate limiting at 20 requests per second:

```bash
wafmap rate-limit https://example.com --rps 20 --window 10
```

Fingerprint TLS stacks with JA4:

```bash
wafmap ja4 https://example.com 443 --debug
```

Probe HTTP/2 support or use fingerprinting mode:

```bash
wafmap http2 https://example.com
wafmap http2fingerprint https://example.com --debug
```

Configuration files for detection and attack payloads live under
`wafmap/plugins/`. You can add or modify YAML files to extend the tool.
