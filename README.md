# SiberKapan 🛡️

**Turkey's Open-Source Cyber Threat Intelligence Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Python%20%2F%20Flask-green.svg)]()
[![Feed](https://img.shields.io/badge/Threat%20Feed-Live-brightgreen.svg)](https://siberkapan.org/api/v1/status)
[![CVE](https://img.shields.io/badge/CVE%20Records-1600%2B-red.svg)](https://siberkapan.org/rss/cve)

SiberKapan is a community-driven threat intelligence platform focused on cyber threats targeting Turkish infrastructure. It aggregates threat data from FortiGate community webhooks, trusted external feeds, and CISA KEV — and delivers it as actionable blocklists, CVE feeds, and REST API endpoints.

🌐 **Live Platform:** [https://siberkapan.org](https://siberkapan.org)  
📡 **API Status:** [https://siberkapan.org/api/v1/status](https://siberkapan.org/api/v1/status)  
📄 **Methodology:** [https://siberkapan.org/metodoloji](https://siberkapan.org/metodoloji)

---

## Features

- **FortiGate Automation Stitch Integration** — Real-time attacker IP submission via webhook
- **Community Blocklists** — TXT, JSON, CIDR, FortiGate CLI, iptables formats
- **CVE Feed** — 1,600+ CISA KEV records with vendor-filtered RSS (Fortinet, Microsoft, Cisco, VMware...)
- **BGP / IP Lookup** — ASN, GeoIP, threat score, source attribution
- **Country & Platform Lists** — RIPE NCC sourced prefix lists for 40+ countries
- **STIX 2.1 Output** — Machine-readable threat intelligence bundle
- **IP Delisting** — False positive reporting and review process
- **TR/EN Bilingual** — Full Turkish and English interface

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Data Sources                        │
│  FortiGate Webhooks │ Feodo │ URLhaus │ Emerging Threats │
│  GreenSnow │ Binary Defense │ CINS │ BotScout │ CISA KEV │
└────────────────────────┬────────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   SiberKapan Core   │
              │   Flask / SQLite    │
              │   APScheduler       │
              │   GeoIP Enrichment  │
              └──────────┬──────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌─────▼────┐   ┌─────▼──────┐
    │REST API │    │ RSS/Atom │   │  Blocklist  │
    │JSON/TXT │    │CVE + IOC │   │  Downloads  │
    │STIX 2.1 │    │Vendor    │   │  TXT/CIDR   │
    └─────────┘    └──────────┘   └────────────┘
```

---

## Quick Start — FortiGate Integration

Add SiberKapan to your FortiGate in 5 minutes:

**1. Create Automation Action (Webhook)**

```
Name: SiberKapan
Protocol: HTTPS
URL: https://siberkapan.org/feed/fortigate
Method: POST
Header: X-SiberKapan-Key: <your-api-key>
Header: Content-Type: application/json
```

**HTTP Body:**
```json
{
  "ip": "%%log.srcip%%",
  "attack_type": "%%log.attack%%",
  "port": %%log.dstport%%,
  "severity": "%%log.severity%%",
  "proto": "%%log.proto%%",
  "src_country": "%%log.srccountry%%",
  "device": "%%log.devname%%"
}
```

**2. Create Automation Stitch**
- Trigger: `IPS Event` or `Anomaly Logs`
- Action: The webhook action above

**3. Request an API Key**  
Contact via [siberkapan.org/iletisim](https://siberkapan.org/iletisim)

---

## API Reference

### Blocklist Endpoints

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/api/v1/list/txt` | TXT | All approved IPs, plaintext |
| `/api/v1/list/json` | JSON | Full IP data with metadata |
| `/api/v1/list/cidr` | CIDR | CIDR notation |
| `/api/v1/list/fortigate` | TXT | FortiGate CLI format |
| `/api/v1/list/iptables` | SH | iptables bash script |
| `/api/v1/list/country/{CC}` | TXT | Country-filtered list |
| `/api/v1/list/platform/{tag}` | TXT | Platform-filtered list |

### CVE / Threat Intel

| Endpoint | Description |
|----------|-------------|
| `/api/v1/cve` | CISA KEV CVE records (JSON) |
| `/api/v1/cve?vendor=fortinet` | Vendor-filtered CVEs |
| `/api/v1/cve/vendors` | Available vendors with counts |
| `/rss/cve` | CVE RSS feed |
| `/rss/cve?vendor=microsoft` | Vendor-filtered CVE RSS |
| `/rss/ioc` | IOC RSS feed |
| `/api/v1/stix` | STIX 2.1 bundle |
| `/api/v1/bgp/{ip}` | IP reputation & BGP lookup |
| `/api/v1/status` | Platform status |

### Example

```bash
# Get full blocklist
curl https://siberkapan.org/api/v1/list/txt

# Get Fortinet CVEs as JSON
curl https://siberkapan.org/api/v1/cve?vendor=fortinet

# Submit attacker IP (requires API key)
curl -X POST https://siberkapan.org/feed/fortigate \
  -H "Content-Type: application/json" \
  -H "X-SiberKapan-Key: YOUR_KEY" \
  -d '{"ip":"1.2.3.4","attack_type":"ssh_brute_force","severity":"high","port":22}'

# STIX 2.1 bundle (high confidence only)
curl "https://siberkapan.org/api/v1/stix?limit=100&min_score=75"
```

---

## Threat Scoring

| Source | Score Bump | Notes |
|--------|-----------|-------|
| FortiGate — Critical | +40 | Verified API key, critical severity |
| FortiGate — High | +30 | Verified API key, high severity |
| FortiGate — Medium | +20 | Verified API key, medium severity |
| FortiGate — Low | +10 | Verified API key, low severity |
| External Feed | 50 | Initial score, source dependent |
| Bulk API | +15 | Batch submission |

Scores are cumulative (max 100). See full methodology at [siberkapan.org/metodoloji](https://siberkapan.org/metodoloji).

---

## Data Sources

| Source | Type | Update |
|--------|------|--------|
| FortiGate Community Webhooks | Community | Real-time |
| [Feodo Tracker](https://feodotracker.abuse.ch) | External | 6h |
| [URLhaus](https://urlhaus.abuse.ch) | External | 6h |
| [Emerging Threats](https://rules.emergingthreats.net) | External | 12h |
| [GreenSnow](https://blocklist.greensnow.co) | External | 6h |
| [Blocklist.de](https://www.blocklist.de) | External | 6h |
| [Binary Defense](https://www.binarydefense.com) | External | 6h |
| [CINS Score](http://cinsscore.com) | External | 6h |
| [BotScout](https://raw.githubusercontent.com/firehol/blocklist-ipsets) | External | 6h |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE | Daily |
| [RIPE NCC](https://stat.ripe.net) | Country Prefixes | On-demand |

---

## Tech Stack

- **Backend:** Python 3.12, Flask, SQLAlchemy, APScheduler
- **Database:** SQLite
- **Web Server:** Nginx + Gunicorn
- **Infrastructure:** Ubuntu 24 LTS
- **Standards:** STIX 2.1, RSS/Atom, REST

---

## Recognition

- Member of **Turkey Presidential Cybersecurity Cluster** (Cumhurbaşkanlığı Dijital Dönüşüm Ofisi Siber Güvenlik Kümesi)
- Trademark registered at TÜRKPATENT (Classes 38 & 42)

---

## IP Delisting

If you believe your IP has been incorrectly listed, submit a delisting request at:  
👉 [https://siberkapan.org/delist](https://siberkapan.org/delist)

Every request is reviewed within 48 hours.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

Data from external feeds is subject to the respective source licenses:
- Feodo Tracker: [abuse.ch](https://abuse.ch)
- URLhaus: [abuse.ch](https://abuse.ch)
- Emerging Threats: [Proofpoint](https://rules.emergingthreats.net)
- CISA KEV: Public domain (US Government)

---

## Contact

- **Platform:** [siberkapan.org](https://siberkapan.org)
- **Contact Form:** [siberkapan.org/iletisim](https://siberkapan.org/iletisim)
- **Developer:** [Oktay ALVER](https://www.linkedin.com/in/oktayalver/?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base_contact_details%3B7PtqsXxcQ62UbG%2BVJgWgCg%3D%3D)
