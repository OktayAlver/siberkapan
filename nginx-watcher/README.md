# Nginx Watcher 🔍

**SiberKapan Threat Intelligence Log Monitoring Agent**
Turkey's Open-Source Nginx Log Monitoring Agent for Cyber Threat Intelligence

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Python%203.6%2B-blue.svg)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen.svg)]()
[![SiberKapan](https://img.shields.io/badge/Powered%20by-SiberKapan-00e5ff.svg)](https://siberkapan.org)

Nginx Watcher is an open-source log monitoring agent that integrates with the SiberKapan platform. It monitors your nginx access log in real time, detects attack patterns (404/auth/rate floods, exploit path signatures, scanner User-Agents), and automatically reports attacker IPs to the SiberKapan community.

Uses only the Python standard library — no pip packages required.

---

## Installation

```bash
curl -fsSL https://siberkapan.org/nginx-watcher/install.sh | sudo bash -s -- --key=YOUR_API_KEY
```

Interactive (without a key argument):

```bash
curl -fsSL https://siberkapan.org/nginx-watcher/install.sh | sudo bash
```

**Requirements:**
- A Linux server running nginx (Ubuntu/Debian/CentOS)
- Python 3.6+
- Root privileges
- A SiberKapan API key → [siberkapan.org/iletisim](https://siberkapan.org/iletisim)

The install script is idempotent — running it again preserves your existing config (custom thresholds, ignore lists) and only updates the agent binary and systemd unit.

---

## How It Works

```
Attacker → Nginx (access.log) → Nginx Watcher → SiberKapan API
                                       │
                              Pattern engine (5 types)
                              Cooldown + bot filtering
                                       │
                              Threshold crossed → automatic
                              POST /feed/nginx
                                       │
                              Entire community protected
```

The agent tails the log file via polling (default: every 1 second) and automatically reopens the file after logrotate. Known good bots/crawlers (Googlebot, ClaudeBot, Bingbot, etc.) are fully excluded from pattern detection.

---

## Detected Patterns

| Pattern | Default Threshold | What It Catches |
|---------|-------------------|------------------|
| `404_flood` | 10×404 in 60s | Directory/endpoint scanning |
| `auth_flood` | 8×401/403 in 60s | Brute-force login attempts |
| `rate_flood` | 30 requests in 10s | Bot/scanner request rate |
| `path_signature` | Instant | Known exploit path signatures (`/wp-login.php`, `/.env`, `/.git/config`, etc.) |
| `ua_signature` | Instant | Known scanning tool UAs (`sqlmap`, `nikto`, `nmap`, etc.) |

A default 30-minute cooldown is applied per IP+pattern combination — the same attack is not reported repeatedly.

---

## Configuration

After installation, customize via `/etc/siberkapan-nginx-watcher/config.json`:

```json
{
  "api_key": "...",
  "api_url": "https://siberkapan.org/feed/nginx",
  "log_path": "/var/log/nginx/access.log",
  "poll_interval_s": 1.0,
  "cooldown_s": 1800,
  "thresholds": {
    "404_flood": {"enabled": true, "count": 10, "window_s": 60},
    "auth_flood": {"enabled": true, "count": 8, "window_s": 60},
    "rate_flood": {"enabled": true, "count": 30, "window_s": 10},
    "path_signature": {"enabled": true},
    "ua_signature": {"enabled": true, "flag_empty_ua": false}
  },
  "ignore_ips": [],
  "ignore_path_prefixes": [],
  "log_file": "/var/log/siberkapan-nginx-watcher.log"
}
```

Restart the service after making changes: `sudo systemctl restart siberkapan-nginx-watcher`

---

## Service Management

```bash
# Status
systemctl status siberkapan-nginx-watcher

# Start / Stop / Restart
systemctl start siberkapan-nginx-watcher
systemctl stop siberkapan-nginx-watcher
systemctl restart siberkapan-nginx-watcher

# Live log
journalctl -u siberkapan-nginx-watcher -f

# File log
tail -f /var/log/siberkapan-nginx-watcher.log
```

---

## SiberKapan Integration

When a pattern threshold is crossed, the agent automatically reports to the SiberKapan API:

```
POST https://siberkapan.org/feed/nginx
X-SiberKapan-Key: <api_key>

{
  "ip": "1.2.3.4",
  "pattern_type": "path_signature",
  "detail": {
    "path": "/wp-login.php",
    "status": 404,
    "hit_count": 1
  }
}
```

Reported IPs are added to the SiberKapan database, shared with the entire community, included in blocklists, and — depending on eligibility — reported to AbuseIPDB.

---

## Manual Run (Debug)

```bash
cd /opt/siberkapan-nginx-watcher
python3 nginx_watcher.py --config /etc/siberkapan-nginx-watcher/config.json --verbose
```

---

## License

MIT License — [siberkapan.org](https://siberkapan.org)
