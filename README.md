# SiberKapan 🛡️

**Turkey's Open-Source Cyber Threat Intelligence Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Python%20%2F%20Flask-green.svg)]()
[![Feed](https://img.shields.io/badge/Threat%20Feed-Live-brightgreen.svg)](https://siberkapan.org/api/v1/status)
[![MISP](https://img.shields.io/badge/MISP-Official%20Feed-blueviolet.svg)](https://siberkapan.org/misp-feed/manifest.json)
[![TAXII](https://img.shields.io/badge/TAXII-2.1-orange.svg)](https://siberkapan.org/taxii/)
[![CVE](https://img.shields.io/badge/CVE%20Records-1600%2B-red.svg)](https://siberkapan.org/rss/cve)

SiberKapan is a community-driven threat intelligence platform focused on cyber threats targeting Turkish infrastructure. It aggregates threat data from FortiGate community webhooks, honeypot sensors, Nginx log analysis, Fail2ban, and trusted external feeds — delivering actionable blocklists, STIX 2.1 bundles, TAXII 2.1 endpoints, and REST API outputs.

🌐 **Live Platform:** [https://siberkapan.org](https://siberkapan.org)
📡 **API Status:** [https://siberkapan.org/api/v1/status](https://siberkapan.org/api/v1/status)
📄 **Methodology:** [https://siberkapan.org/metodoloji](https://siberkapan.org/metodoloji)
📊 **Threat Reports:** [https://siberkapan.org/tehdit-raporlari](https://siberkapan.org/tehdit-raporlari)

---

## Recognition & Ecosystem Integration

| Platform | Status | Details |
|----------|--------|---------|
| **MISP** | ✅ Official Feed | Feed PR merged — [manifest](https://siberkapan.org/misp-feed/manifest.json) |
| **AbuseIPDB** | ✅ Webmaster & Contributor | Active IP reporting |
| **AlienVault OTX** | ✅ Pulse Publisher | Daily IOC pulses |
| **Spamhaus** | ✅ Submission Partner | Active IP reporting |
| **TAXII 2.1** | ✅ Live | [https://siberkapan.org/taxii/](https://siberkapan.org/taxii/) |
| **Suricata IDS** | ✅ Export | `/api/v1/export/suricata` |
| **Wazuh SIEM** | ✅ Export | `/api/v1/export/wazuh-cdb` |
| **TR Presidential Cybersecurity Cluster** | ✅ Member | Cumhurbaşkanlığı DDO Siber Güvenlik Kümesi |

---

## Features

- **FortiGate Automation Stitch Integration** — Real-time attacker IP submission via webhook from FortiGate Security Fabric
- **HoneypotKapan** — Open-source honeypot emulating 11 services (SSH, RDP, FTP, Telnet, SMB, MySQL, MSSQL, VNC, HTTP, SIP, SMTP); one-command install
- **Malware Sample Capture** — SSH honeypot safely fingerprints malware attackers attempt to download (SHA256, SSRF-protected, never written to disk or executed), enriched via MalwareBazaar — see [siberkapan.org/malware-samples](https://siberkapan.org/malware-samples)
- **Sigma Rule Export** — SIEM-agnostic detection rules (`/api/v1/export/sigma`) for Splunk, Elastic, Sentinel, QRadar via pySigma
- **Nginx Watcher** — Zero-dependency Python agent detecting 404/auth/rate floods and exploit signatures from nginx access logs
- **Fail2ban Integration** — Automated ban event reporting
- **MISP Official Feed** — STIX-compatible JSON feed, accepted into the MISP ecosystem
- **TAXII 2.1 Server** — Standard protocol for enterprise SIEM/SOAR integration (Anomali, ThreatConnect, CERT platforms)
- **Delta / Incremental Feed** — `?since=` parameter and ETag support to minimize bandwidth
- **ASN Abuse Notification** — Automatic weekly abuse reports to network operators (Shadowserver model)
- **AbuseIPDB / OTX / Spamhaus Reporting** — Active contributor to global threat databases
- **IP Aging & Decay** — Automatic score decay and delisting for inactive IPs
- **Community Blocklists** — TXT, JSON, CIDR, FortiGate CLI, iptables, Suricata rules, Wazuh CDB formats
- **CVE Feed** — 1,600+ CISA KEV records with vendor-filtered RSS
- **BGP / IP Lookup** — ASN, GeoIP, threat score, source attribution
- **STIX 2.1 Output** — Machine-readable threat intelligence bundle
- **IP Delisting** — False positive reporting with Cloudflare Turnstile protection
- **TR/EN Bilingual** — Full Turkish and English interface
- **Threat Reports** — Periodic threat intelligence reports with novel detection analysis

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          Data Sources                             │
│  FortiGate Webhooks │ HoneypotKapan │ Nginx Watcher │ Fail2ban   │
│  Feodo │ URLhaus │ Emerging Threats │ CISA KEV                   │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │   SiberKapan Core   │
                │   Flask / SQLite    │
                │   APScheduler       │
                │   GeoIP Enrichment  │
                │   IP Decay Engine   │
                └──────────┬──────────┘
                           │
      ┌────────────────────┼────────────────────┐
      │                    │                    │
 ┌────▼────┐         ┌─────▼────┐        ┌─────▼──────┐
 │REST API │         │ TAXII    │        │  Reporting  │
 │STIX 2.1 │         │ 2.1      │        │  AbuseIPDB  │
 │Delta    │         │ MISP     │        │  OTX        │
 │Suricata │         │ Feed     │        │  Spamhaus   │
 │Wazuh    │         │          │        │  ASN Notify │
 │Sigma    │         │          │        │             │
 └─────────┘         └──────────┘        └────────────┘
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

## Quick Start — Honeypot & Nginx Watcher

| Agent | What It Detects | Install |
|-------|-----------------|---------|
| [HoneypotKapan](honeypot/) | SSH, RDP, FTP, Telnet, SMB, MySQL, MSSQL, VNC, HTTP, SIP, SMTP | `wget https://siberkapan.org/honeypot/install.py && sudo python3 install.py` |
| [Nginx Watcher](nginx-watcher/) | 404/auth/rate flood, exploit path signatures, scanner UAs | `curl -fsSL https://siberkapan.org/nginx-watcher/install.sh \| sudo bash -s -- --key=YOUR_KEY` |

---

## API Reference

### Feed Endpoints (Delta/ETag supported)

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/api/v1/view/all-feed` | TXT | All sources combined — supports `?since=` |
| `/api/v1/view/fortigate-feed` | TXT | FortiGate community feed — supports `?since=` |
| `/api/v1/view/honeypot-feed` | TXT | HoneypotKapan feed — supports `?since=` |
| `/api/v1/view/nginx-feed` | TXT | Nginx Watcher feed — supports `?since=` |

**Delta fetch example:**
```bash
# Only IPs added after a specific timestamp
curl "https://siberkapan.org/api/v1/view/all-feed?since=2026-07-01T00:00:00Z"

# ETag-based caching (returns 304 if unchanged)
curl -H "If-None-Match: \"sk-abc123\"" https://siberkapan.org/api/v1/view/all-feed
```

### Blocklist Export Endpoints

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/api/v1/list/txt` | TXT | All approved IPs, plaintext |
| `/api/v1/list/json` | JSON | Full IP data with metadata |
| `/api/v1/list/cidr` | CIDR | CIDR notation |
| `/api/v1/list/fortigate` | TXT | FortiGate CLI format |
| `/api/v1/list/iptables` | SH | iptables bash script |
| `/api/v1/export/suricata` | rules | Suricata IDS drop/alert rules |
| `/api/v1/export/wazuh-cdb` | CDB | Wazuh SIEM CDB list |
| `/api/v1/export/sigma` | YAML | Sigma detection rule (SIEM-agnostic) |

**Suricata integration:**
```bash
curl -o /etc/suricata/rules/siberkapan.rules \
  "https://siberkapan.org/api/v1/export/suricata?min_score=75"
```

**Wazuh integration:**
```bash
curl -o /var/ossec/etc/lists/siberkapan-blocklist \
  "https://siberkapan.org/api/v1/export/wazuh-cdb?min_score=75"
```

**Sigma integration:**
```bash
curl -o siberkapan.yml "https://siberkapan.org/api/v1/export/sigma?min_score=40"
```

### TAXII 2.1 Endpoints

| Endpoint | Description |
|----------|-------------|
| `/taxii/` | Discovery |
| `/taxii/api-root/` | API Root |
| `/taxii/api-root/collections/` | Collections list |
| `/taxii/api-root/collections/{id}/objects/` | STIX objects (supports `added_after`) |
| `/taxii/api-root/collections/{id}/manifest/` | Object manifest |

**Collections:**

| ID | Name | Description |
|----|------|-------------|
| `a1b2c3d4-0001-4000-8000-siberkapan01` | All Threats | All approved IPs |
| `a1b2c3d4-0002-4000-8000-siberkapan02` | High Risk | Score 75+ |
| `a1b2c3d4-0003-4000-8000-siberkapan03` | Honeypot | Honeypot detections |

```bash
# TAXII discovery
curl -H "Accept: application/taxii+json;version=2.1" https://siberkapan.org/taxii/

# Fetch STIX objects
curl "https://siberkapan.org/taxii/api-root/collections/a1b2c3d4-0001-4000-8000-siberkapan01/objects/?limit=100"
```

### MISP Feed

```
https://siberkapan.org/misp-feed/manifest.json
```

Add to MISP: Administration → Feeds → Add Feed → URL: `https://siberkapan.org/misp-feed/`

### CVE / Threat Intel

| Endpoint | Description |
|----------|-------------|
| `/api/v1/cve` | CISA KEV CVE records (JSON) |
| `/api/v1/cve?vendor=fortinet` | Vendor-filtered CVEs |
| `/rss/cve` | CVE RSS feed |
| `/rss/ioc` | IOC RSS feed |
| `/api/v1/stix` | STIX 2.1 bundle |
| `/api/v1/bgp/{ip}` | IP reputation & BGP lookup |
| `/api/v1/ip/{ip}` | IP threat intelligence lookup (JSON) |
| `/api/v1/status` | Platform status |

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

Scores are cumulative (max 100). IPs decay at -2 points/day after 30 days of inactivity and are automatically delisted below score 15.

---

## Data Sources

| Source | Type | Update |
|--------|------|--------|
| FortiGate Community Webhooks | Community | Real-time |
| HoneypotKapan Sensors | Community | Real-time |
| Nginx Watcher Agents | Community | Real-time |
| Fail2ban Reports | Community | Real-time |
| [Feodo Tracker](https://feodotracker.abuse.ch) | External | 6h |
| [URLhaus](https://urlhaus.abuse.ch) | External | 6h |
| [Emerging Threats](https://rules.emergingthreats.net) | External | 12h |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE | Daily |
| [RIPE NCC](https://stat.ripe.net) | Country Prefixes | On-demand |

---

## Security & Data Quality

Building a threat intelligence platform introduces unique challenges around data integrity, false positives, and adversarial manipulation. SiberKapan addresses these systematically:

### IP Aging & Automatic Delisting

Threat scores are not permanent. An IP that was part of a botnet three months ago may have been reassigned to a legitimate user. SiberKapan implements a time-based decay mechanism modeled after AbuseIPDB's own scoring philosophy:

- **Grace period:** IPs with recent activity (last 30 days) are protected from decay
- **Daily decay:** After the grace period, the threat score decreases by 2 points per day
- **Automatic delisting:** When a score drops below 15, the IP is removed from all feeds and blocklists — but the record is retained for audit purposes
- **Natural reset:** Any new detection resets the decay counter, preventing premature delisting of persistent threats
- **Implementation:** Decay runs as a bulk database operation rather than row-by-row updates, preventing lock contention in a concurrent multi-worker environment

### False Positive Prevention

**Infrastructure allowlisting:** CDN and cloud proxy infrastructure (Cloudflare, Fastly, AWS CloudFront, Google) is automatically excluded from threat feeds. When a reverse proxy sits in front of a monitored web server, naive log analysis would flag the proxy's edge nodes as attackers. SiberKapan resolves this by cross-referencing detected IPs against official published CIDR ranges from each provider — updated every 24 hours. IPs identified as infrastructure are tagged and excluded from feeds, novel detection calculations, and AbuseIPDB reporting.

**UDP spoofing protection:** UDP connections cannot be attributed to a verified source IP due to the connectionless nature of the protocol and the feasibility of source address spoofing. All UDP-only detections (UDP flood, UDP scan, session-based UDP anomalies) are retained in the internal database for traffic analysis but are explicitly excluded from:
- All public feed endpoints
- AbuseIPDB submissions
- MISP feed events
- ASN abuse notifications

This is consistent with AbuseIPDB's own reporting policy, which explicitly disallows UDP-based submissions due to the same spoofing concerns. The exclusion is enforced at the data pipeline level, not as a UI filter — meaning UDP-only IPs cannot reach any external reporting channel regardless of how the submission is triggered.

**Novel detection methodology:** The platform's "novel detection" metric (percentage of IPs not previously known to AbuseIPDB) is calculated only against organically detected IPs — honeypot, FortiGate, Nginx Watcher, and Fail2ban sources. External feed aggregations (Feodo Tracker, URLhaus, Emerging Threats) are excluded from this calculation, as they consist of already-known global threats and would artificially deflate the metric.

### Data Poisoning & Abuse Prevention

**Source verification:** FortiGate webhook submissions require a pre-issued API key. The key is bound to a specific contributor account and is used to attribute detections to a verified sensor. Unkeyed submissions are rejected.

**Private IP rejection:** RFC 1918 private address space (10.x.x.x, 172.16.x.x, 192.168.x.x) and loopback addresses are rejected at the ingestion layer. These cannot represent real external threats and are a common vector for poisoning community blocklists.

**Delisting with verification:** Delisting requests require a valid email address, pass Cloudflare Turnstile bot detection, and are rate-limited to 3 requests per 24 hours per submitter. All requests are manually reviewed; approved delistings are recorded for audit purposes.

**Multi-source corroboration:** An IP detected by multiple independent sources (e.g., both a honeypot and a FortiGate sensor from different organizations) receives a higher confidence score. Single-source detections are scored conservatively.

### Malware Sample Handling

SiberKapan's SSH honeypot captures malware samples that attackers attempt to download, without ever storing or executing them:

- **SSRF protection:** The download URL's hostname is resolved and every returned address is validated as a public IP before any connection is made — private, loopback, link-local, and cloud-metadata addresses are rejected. The validated IP is connected to directly (not re-resolved), preventing DNS-rebinding bypass.
- **No persistence:** The file is streamed, hashed (SHA256), and discarded — it is never written to disk and never executed.
- **Bounded fetch:** 5MB size cap, 8-second timeout, maximum 3 redirects (each independently re-validated).
- **Enrichment, not storage:** Captured hashes are checked against [MalwareBazaar](https://bazaar.abuse.ch) to identify known malware families, without SiberKapan ever hosting the file itself.

---

- **Standards:** STIX 2.1, TAXII 2.1, RSS/Atom, REST
- **Integrations:** MISP, AbuseIPDB, AlienVault OTX, Spamhaus, Suricata, Wazuh

---

## Threat Reports

Periodic threat intelligence reports analyzing detection trends, novel threat discovery rates, and attack pattern analysis.

- [Sayı 1 — June–July 2026](https://siberkapan.org/tehdit-raporlari/sayi-1) | [EN PDF](https://siberkapan.org/static/reports/siberkapan-tehdit-raporu-sayi1-en.pdf) | [TR PDF](https://siberkapan.org/static/reports/siberkapan-tehdit-raporu-sayi1-tr.pdf)

---

## IP Delisting

If you believe your IP has been incorrectly listed:
👉 [https://siberkapan.org/delist](https://siberkapan.org/delist)

Every request is reviewed within 48 hours. Bot protection via Cloudflare Turnstile.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contact

- **Platform:** [siberkapan.org](https://siberkapan.org)
- **Contact Form:** [siberkapan.org/iletisim](https://siberkapan.org/iletisim)
- **Developer:** [Oktay ALVER](https://www.linkedin.com/in/oktayalver/)
