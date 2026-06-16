# HoneypotKapan 🪤

**SiberKapan Tehdit İstihbarat Honeypotu**  
Turkey's Open-Source Cyber Threat Intelligence Honeypot

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2020%2B-orange.svg)]()
[![SiberKapan](https://img.shields.io/badge/Powered%20by-SiberKapan-00e5ff.svg)](https://siberkapan.org)

HoneypotKapan, SiberKapan platformuyla entegre çalışan açık kaynak bir honeypot sistemidir. Saldırganları sahte servislerle tuzağa düşürür, credential'larını loglar ve tespit edilen IP'leri SiberKapan topluluğuyla otomatik olarak paylaşır.

---

## Kurulum

```bash
wget https://siberkapan.org/honeypot/install.py
sudo python3 install.py
```

**Gereksinimler:**
- Ubuntu 20.04+ veya Debian 11+
- Python 3.8+
- Root yetkisi
- SiberKapan API anahtarı → [siberkapan.org/iletisim](https://siberkapan.org/iletisim)

---

## Nasıl Çalışır?

```
İnternet → Firewall (NAT) → HoneypotKapan Sunucu
                                      │
                              Sahte servis yanıtı
                              Credential loglama
                                      │
                              3. denemede otomatik
                              SiberKapan API bildirimi
                                      │
                              Tüm topluluk korunur
```

---

## Desteklenen Servisler

| Servis | Honeypot Port | Gerçek Port | Ne Yakalar |
|--------|--------------|-------------|------------|
| SSH | 10022 | 22 | Username + Password |
| FTP | 10021 | 21 | Username + Password |
| Telnet | 10023 | 23 | Username + Password |
| RDP | 13389 | 3389 | Bağlantı + Username |
| SMB | 10445 | 445 | Bağlantı + Username |
| MSSQL | 11433 | 1433 | Username |
| MySQL | 13306 | 3306 | Username |
| VNC | 15900 | 5900 | Şifre hash'i |
| HTTP | 18080 | 8080 | Username + Password |
| SIP | 15060 | 5060 | SIP kullanıcı adı |

---

## Firewall NAT Yapılandırması

Kurulum tamamlandığında ekranda gösterilir:

```
════════════════════════════════════════════════════════════
  Bu sunucunun ic IP adresi: 192.168.1.100
════════════════════════════════════════════════════════════
  Dis Port     Hedef                          Servis
  ──────────────────────────────────────────────────────────
  22           192.168.1.100:10022            SSH
  3389         192.168.1.100:13389            RDP
  21           192.168.1.100:10021            FTP
  ...
════════════════════════════════════════════════════════════

  Saldırı alacak olan honeypot portlarını, iç sunucunuzda
  belirtilen portlara yönlendirin.
  Örneğin 22 için sunucunuzun 192.168.1.100:10022 gibi.
```

FortiGate, MikroTik, Palo Alto veya kullandığınız herhangi bir firewall'da bu NAT kurallarını oluşturun.

---

## Log Dosyaları

```
/var/log/honeypotkapan/
├── honeypotkapan.log    # Servis logu
├── events.log           # Tüm olaylar (JSON)
└── credentials.log      # Yakalanan credential'lar (JSON)
```

**Örnek events.log:**
```json
{"timestamp":"2026-06-16T10:30:00Z","service":"ssh","ip":"1.2.3.4","port":10022,"username":"admin","password":"123456","extra":{}}
{"timestamp":"2026-06-16T10:30:05Z","service":"ftp","ip":"1.2.3.4","port":10021,"username":"root","password":"toor","extra":{}}
{"timestamp":"2026-06-16T10:31:00Z","service":"http","ip":"1.2.3.4","port":18080,"username":"admin","password":"admin123","extra":{"method":"POST","path":"/login"}}
```

---

## Servis Yönetimi

```bash
# Durum
systemctl status honeypotkapan

# Başlat / Durdur / Yeniden başlat
systemctl start honeypotkapan
systemctl stop honeypotkapan
systemctl restart honeypotkapan

# Canlı log
journalctl -u honeypotkapan -f

# Olay logu
tail -f /var/log/honeypotkapan/events.log

# Credential logu
tail -f /var/log/honeypotkapan/credentials.log
```

---

## SiberKapan Entegrasyonu

HoneypotKapan, bir IP **3 kez** bağlantı denemesi yaptığında SiberKapan API'ye otomatik bildirim gönderir:

```
POST https://siberkapan.org/feed/honeypot
X-SiberKapan-Key: <api_key>

{
  "ip": "1.2.3.4",
  "attack_type": "honeypot_ssh",
  "port": 10022,
  "sensor": "HoneypotKapan"
}
```

Bildirilen IP'ler SiberKapan veritabanına eklenerek tüm toplulukla paylaşılır ve blocklist'e dahil edilir.

---

## Lisans

MIT License — [siberkapan.org](https://siberkapan.org)
