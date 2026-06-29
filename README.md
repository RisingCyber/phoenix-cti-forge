# 🔥 Phoenix CTI Forge v2.3

**Cyber Threat Intelligence Educational Platform**  
*Created by Australian Phoenix CyberOps*


---

## Overview

Phoenix CTI Forge is a self-hosted, offline-capable web application for learning,
practicing, and applying Cyber Threat Intelligence (CTI) analysis skills. Built for
analysts, by analysts with no external API calls and no data retention.

---

## Features

| Module | Description |
|---|---|
| **IOC Analyzer** | Extracts 12 IOC types (IP, domain, URL, hashes, CVE, email, BTC, registry) from raw text with auto defang and hunt query generation |
| **Defang / Re-fang Tool** | Bulk or single IOC defanging/re-fanging — the #1 daily CTI analyst task |
| **MITRE ATT&CK Explorer** | Browse all 14 tactics with curated techniques, CTI insights, APT examples, and detection tips |
| **TTP Mapper** | Map natural-language behavior descriptions to ATT&CK techniques |
| **Training Center** | 30+ interactive quiz questions across 6 categories with full explanations and learning paths |
| **Report Builder** | Generate structured threat reports from professional templates |

---

## Bugs Fixed (v2.3)

1. **`ioc_engine.py`** SHA256 hunt query had a stray `\t\t}` tab causing `IndentationError`
2. **`ioc_engine.py`** IPv4 Sigma hunt query used wrong key `sha256:` instead of `DestinationIp:`
3. **`educational.py`** True/False `correct_answer` was string `"True"`/`"False"` but JS submits `"A"`/`"B"`; corrected to letter format
4. **`ioc_engine.py`** IOC extraction now auto-refangs input first (handles defanged IOCs in intel reports)

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run (development)
python app.py

# 3. Open browser
# http://127.0.0.1:5000
```

---

## Security Notes

- All analysis runs server-side with **no external API calls**
- **No data is logged, stored, or transmitted** to third parties
- Input validated and sanitized on all endpoints
- Rate limiting: 200/day, 50/hour default; stricter limits on analysis endpoints
- CSRF protection via Flask-WTF
- Security headers via Flask-Talisman (CSP, X-Frame-Options, etc.)
- For educational / air-gapped / controlled environments only
- Do not expose to the internet without proper hardening

---

## License

For educational purposes only.  
**Created by Australian Phoenix CyberOps**
