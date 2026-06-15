# FortiGate Webhook Integration Guide

SiberKapan accepts real-time attacker IP submissions from FortiGate devices via Automation Stitch webhooks.

## Prerequisites

- FortiGate device with firmware 6.4+
- SiberKapan API key (request via [siberkapan.org/iletisim](https://siberkapan.org/iletisim))
- HTTPS access to siberkapan.org (port 443)

---

## Step 1 — Create Automation Action

In FortiGate GUI:  
**Security Fabric → Automation → Action → Create New**

| Field | Value |
|-------|-------|
| Name | `SiberKapan` |
| Action Type | `Webhook` |
| Protocol | `HTTPS` |
| URL | `siberkapan.org/feed/fortigate` |
| Port | `443` |
| Method | `POST` |
| TLS Certificate | OFF |
| Verify Remote Host | OFF |

**HTTP Headers:**
```
Content-Type: application/json
X-SiberKapan-Key: <your-api-key>
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

> ⚠️ Note: `%%log.dstport%%` is written without quotes (integer). If your FortiGate version returns an error, wrap it in quotes: `"%%log.dstport%%"`

---

## Step 2 — Create Automation Stitch

**Security Fabric → Automation → Stitch → Create New**

| Field | Value |
|-------|-------|
| Name | `AttackerBlockAutomation` |
| Status | Enabled |
| Trigger | `IPS Event` or `Anomaly Logs` |
| Action | `SiberKapan` (created above) |

### Recommended Trigger: IPS Event
IPS Event provides richer attack metadata (attack name, severity, protocol) compared to Anomaly Logs.

### Using Anomaly Logs
If you prefer Anomaly Logs, ensure your trigger severity is set to **High** or above to avoid false positives from legitimate high-bandwidth sources.

---

## Step 3 — Test the Integration

**Via FortiGate CLI:**
```
config vdom
edit root
diagnose automation test AttackerBlockAutomation
end
```

A successful submission returns:
```json
{
  "status": "accepted",
  "ip": "x.x.x.x",
  "threat_score": 30,
  "approved": true,
  "attack_type": "..."
}
```

**Monitor submissions:**  
View your device's contributions at [siberkapan.org/fortigate-feed](https://siberkapan.org/fortigate-feed)

---

## Internal Network Access

If your FortiGate cannot reach external URLs directly, you can use the server's IP address:

```
URL: https://104.247.186.100/feed/fortigate
Port: 443
Verify Remote Host: OFF
```

---

## Scoring

Submissions from verified API keys are automatically approved and scored based on severity:

| Severity | Score Added |
|----------|------------|
| Critical | +40 |
| High | +30 |
| Medium | +20 |
| Low / Unknown | +10 |

Scores accumulate per IP (max 100). The same IP reported multiple times increases its threat score.

---

## Privacy

- Your FortiGate's IP address is hashed (SHA-256) before storage — the actual IP is never saved
- Device hostname (`%%log.devname%%`) is stored as the source name but is not displayed publicly
- Contributor country is derived from your IP for geographic statistics only

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `404 Not Found` | Wrong URL | Use `siberkapan.org/feed/fortigate` (no trailing slash) |
| `401 Unauthorized` | Missing/wrong API key | Check `X-SiberKapan-Key` header |
| `400 Bad Request` | Invalid IP in payload | Check `%%log.srcip%%` variable |
| `automation test failed(2)` | SSL verification | Set `Verify Remote Host: OFF` |
| No data in dashboard | VDOM mismatch | Run test from correct VDOM |

---

## Support

Contact: [siberkapan.org/iletisim](https://siberkapan.org/iletisim)
