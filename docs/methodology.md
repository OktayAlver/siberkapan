# Data Methodology

This document describes how SiberKapan collects, validates, scores, and publishes threat intelligence data.

## Data Collection

Threat data is collected from three channels:

### 1. Community Contributions (FortiGate Webhooks)
Verified members with API keys submit attacker IPs via FortiGate Automation Stitch webhooks in real time. Each submission includes attack type, severity, protocol, and source country as detected by the FortiGate IPS engine.

### 2. External Feeds
Nine external threat intelligence feeds are pulled automatically every 6–12 hours:

| Feed | Provider | Update |
|------|----------|--------|
| Feodo Tracker (aggressive) | abuse.ch | 6h |
| Feodo Tracker (standard) | abuse.ch | 6h |
| URLhaus | abuse.ch | 6h |
| Emerging Threats | Proofpoint | 12h |
| GreenSnow | greensnow.co | 6h |
| Blocklist.de Bots | blocklist.de | 6h |
| Binary Defense Banlist | binarydefense.com | 6h |
| CINS Score Bad Guys | cinsscore.com | 6h |
| BotScout (FireHOL) | firehol/blocklist-ipsets | 6h |

### 3. CISA KEV (CVE Data)
The CISA Known Exploited Vulnerabilities catalog is fetched daily. 1,600+ CVE records are stored and served with vendor-based filtering via RSS and JSON API.

---

## Validation

Every incoming IP is validated before storage:

1. **Format check** — RFC 791 compliance
2. **Private range rejection** — RFC 1918 (10.x, 172.16–31.x, 192.168.x), loopback (127.x), multicast (224.x–239.x) are automatically rejected
3. **Duplicate handling** — existing IPs receive a score increment instead of a new record

**Approval rules:**
- External feed IPs → automatically approved
- FortiGate webhook IPs with valid API key → automatically approved
- Community reports without API key → enter moderation queue

---

## Threat Scoring

Each IP receives a threat score (0–100):

| Source / Event | Score | Notes |
|----------------|-------|-------|
| FortiGate — Critical severity | +40 | API key required |
| FortiGate — High severity | +30 | API key required |
| FortiGate — Medium severity | +20 | API key required |
| FortiGate — Low / Unknown | +10 | API key required |
| External feed (initial) | 50 | Source dependent |
| Bulk API submission | +15 | API key required |

- Scores are **cumulative** — same IP reported multiple times increases score
- Maximum score: **100**
- Scores do **not decay** over time in the current version
- To remove or reduce a score, submit a [delisting request](https://siberkapan.org/delist)

---

## GeoIP Enrichment

After an IP is stored, GeoIP enrichment runs asynchronously:

- **Provider:** ip-api.com
- **Data collected:** country code, country name, city, ASN, AS organization, ISP, datacenter/proxy/VPN flag
- **Accuracy note:** GeoIP data is approximate. VPNs, Tor exit nodes, and cloud provider IPs may show incorrect locations.

---

## Publication

Approved IPs are immediately available via:

- REST API (TXT, JSON, CIDR, FortiGate CLI, iptables)
- RSS/Atom feeds (IOC and CVE)
- STIX 2.1 bundle
- Country and platform filtered lists (via RIPE NCC API)

---

## AbuseIPDB Comparison

SiberKapan periodically cross-references its database against AbuseIPDB to measure original detection coverage. IPs in SiberKapan that have zero AbuseIPDB reports represent threats detected through the FortiGate community network ahead of global reporting.

This comparison runs automatically every 6 hours. Results are published at [siberkapan.org/metodoloji](https://siberkapan.org/metodoloji).

---

## Known Limitations

- **Geographic coverage:** SiberKapan focuses on threats targeting Turkish infrastructure. It does not claim global coverage.
- **No score decay:** Threat scores do not automatically decrease over time.
- **GeoIP accuracy:** Approximate, especially for VPNs, proxies, and cloud providers.
- **External feed dependency:** If an external feed is unreachable, that category is not updated until the next scheduled pull.
- **False positive risk:** Community submissions may contain false positives. The [IP delisting form](https://siberkapan.org/delist) exists to address this.

---

## Provenance

Every IP record stores:

| Field | Description |
|-------|-------------|
| `ip_address` | The attacker IP |
| `score` | Threat score 0–100 |
| `first_seen` | First detection timestamp |
| `last_seen` | Most recent detection timestamp |
| `report_count` | Total number of reports |
| `source_type` | `fortigate` / `external` / `honeypot` / `bulk` |
| `source_name` | Feed name (feodo, urlhaus, etc.) |
| `attack_type` | Attack classification |
| `country_code` | ISO 3166-1 alpha-2 |
| `asn` | Autonomous System Number |
| `asn_org` | AS Organization name |
| `platform_tag` | Cloud provider tag (google-cloud, amazon-aws, etc.) |

---

## IP Delisting

Any IP owner can request removal via [siberkapan.org/delist](https://siberkapan.org/delist) or the API:

```bash
curl -X POST https://siberkapan.org/api/v1/delist \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "reason": "This IP belongs to our organization and is not an attack source.",
    "contact": "abuse@example.com"
  }'
```

Requests are reviewed within 48 hours.
