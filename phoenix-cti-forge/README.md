# 🔥 Phoenix CTI Forge v2.0

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
| **🆕 Defang / Re-fang Tool** | Bulk or single IOC defanging/re-fanging — the #1 daily CTI analyst task |
| **MITRE ATT&CK Explorer** | Browse all 14 tactics with curated techniques, CTI insights, APT examples, and detection tips |
| **TTP Mapper** | Map natural-language behavior descriptions to ATT&CK techniques |
| **Training Center** | 30+ interactive quiz questions across 6 categories with full explanations and learning paths |
| **Report Builder** | Generate structured threat reports from professional templates |

---

## Bugs Fixed (v2.0)

1. **`config.py`** — `APP_NAME` was `"CTI Forge"`, renamed to `"Phoenix CTI Forge"`
2. **`app.py`** — `inject_globals()` referenced `'Phoenix_APP_VERSION'` (typo); corrected to `'APP_VERSION'`
3. **`ioc_engine.py`** — SHA256 hunt query had a stray `\t\t}` tab causing `IndentationError`
4. **`ioc_engine.py`** — IPv4 Sigma hunt query used wrong key `sha256:` instead of `DestinationIp:`
5. **`base.html`** — Lock emoji used as logo; replaced with proper yellow phoenix SVG
6. **`training.html`** — Referenced `training_module.QUESTIONS` (not in template context); fixed to use `stats.questions`
7. **`educational.py`** — True/False `correct_answer` was string `"True"`/`"False"` but JS submits `"A"`/`"B"`; corrected to letter format
8. **`educational.py`** — Options had letter prefixes (`A. ...`) causing JS to render `A. A. ...`; stripped to plain text
9. **`ioc_engine.py`** — IOC extraction now auto-refangs input first (handles defanged IOCs in intel reports)

---

## Enhancements (v2.0)

- **Yellow Phoenix SVG logo** throughout header and footer
- **New Defang/Re-fang Tool** page — instantly defang IOCs for safe sharing or re-fang for analysis
- **Auto-refang on IOC extraction** — paste defanged threat reports and still extract all indicators
- **Defanged IOC output** — every extracted IOC now also shows its defanged form
- **30+ training questions** covering: CTI Fundamentals, IOC Analysis, MITRE ATT&CK, Threat Intel Sources, Attribution, Operational CTI, and Scenarios
- **Extended TTP keyword map** — 35+ keywords for ATT&CK mapping
- **Multi-platform hunt queries** — Splunk SPL added alongside KQL and Sigma
- **Credit to Australian Phoenix CyberOps** in footer and startup banner

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

### Production (gunicorn)

```bash
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export FLASK_ENV=production
gunicorn -w 4 -b 127.0.0.1:5000 app:app
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
