**Türkçe** · [🇬🇧 English](README.md)

# SiberKapan 🛡️

**Türkiye'nin Açık Kaynak Siber Tehdit İstihbaratı Platformu**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Python-green.svg)]()
[![Feed](https://img.shields.io/badge/Threat%20Feed-Live-brightgreen.svg)](https://siberkapan.org/api/v1/status)
[![MISP](https://img.shields.io/badge/MISP-Official%20Feed-blueviolet.svg)](https://siberkapan.org/misp-feed/manifest.json)
[![TAXII](https://img.shields.io/badge/TAXII-2.1-orange.svg)](https://siberkapan.org/taxii/)
[![CVE](https://img.shields.io/badge/CVE%20Records-1600%2B-red.svg)](https://siberkapan.org/rss/cve)

SiberKapan, Türkiye altyapısını hedef alan siber tehditlere odaklanan, topluluk destekli bir tehdit istihbaratı platformudur. FortiGate topluluk webhook'ları, honeypot sensörleri, Nginx log analizi, Fail2ban ve güvenilir dış kaynaklardan tehdit verisi toplar — ayrıca Certificate Transparency log izleme ile oltalama ve zararlı alan adlarını gerçek zamanlı tespit eder — eyleme geçirilebilir engelleme listeleri, STIX 2.1 paketleri, TAXII 2.1 uç noktaları ve REST API çıktıları sunar.

🌐 **Canlı Platform:** [https://siberkapan.org](https://siberkapan.org)
📡 **API Durumu:** [https://siberkapan.org/api/v1/status](https://siberkapan.org/api/v1/status)
📄 **Metodoloji:** [https://siberkapan.org/metodoloji](https://siberkapan.org/metodoloji)
📊 **Tehdit Raporları:** [https://siberkapan.org/tehdit-raporlari](https://siberkapan.org/tehdit-raporlari)

---

## Tanınırlık & Ekosistem Entegrasyonu

| Platform | Durum | Detay |
|----------|--------|---------|
| **MISP** | ✅ Resmi Feed | Feed PR'ı merge edildi — [manifest](https://siberkapan.org/misp-feed/manifest.json) |
| **AbuseIPDB** | ✅ Webmaster & Katkıcı | Aktif IP raporlama |
| **AlienVault OTX** | ✅ Pulse Yayıncısı | Günlük IOC pulse'ları |
| **Spamhaus** | ✅ Gönderim Ortağı | Aktif IP raporlama |
| **TAXII 2.1** | ✅ Canlı | [https://siberkapan.org/taxii/](https://siberkapan.org/taxii/) |
| **Suricata IDS** | ✅ Export | `/api/v1/export/suricata` |
| **Wazuh SIEM** | ✅ Export | `/api/v1/export/wazuh-cdb` |
| **Cumhurbaşkanlığı Siber Güvenlik Kümesi** | ✅ Üye | DDO Siber Güvenlik Kümesi |

---

## Özellikler

- **FortiGate Automation Stitch Entegrasyonu** — FortiGate Security Fabric'ten webhook ile gerçek zamanlı saldırgan IP gönderimi
- **Oltalama & Zararlı Alan Adı Tespiti** — Certificate Transparency (CT) log izleme, sertifika yayınlandığı anda oltalama alan adlarını yakalar — çoğu zaman hiçbir şikayet dahi yapılmadan. Marka/niyet kelime eşleştirmesi, bulanık (fuzzy) typosquat tespiti ve Punycode/IDN çözümlemesini birleştirir. [Tespit Metodolojisi →](docs/PHISHING_DETECTION.md)
- **HoneypotKapan** — 11 servisi (SSH, RDP, FTP, Telnet, SMB, MySQL, MSSQL, VNC, HTTP, SIP, SMTP) taklit eden açık kaynak honeypot; tek komutla kurulum
- **Malware Örnek Yakalama** — SSH honeypot, saldırganların indirmeye çalıştığı malware'i güvenli şekilde parmak izler (SHA256, SSRF korumalı, asla diske yazılmaz veya çalıştırılmaz), MalwareBazaar ile zenginleştirilir — bkz. [siberkapan.org/malware-samples](https://siberkapan.org/malware-samples)
- **Alan Adı Canlılık Katmanlama** — Kendi kaynaklı ve USOM kaynaklı alan adları, kademeli DNS/HTTP taramalarıyla sürekli yeniden doğrulanır; resmi listelerin hiç temizlemediği ölü kayıtlardan gerçek tehditleri ayırt eder
- **Sigma Kural Export** — Splunk, Elastic, Sentinel, QRadar için pySigma üzerinden SIEM-bağımsız tespit kuralları (`/api/v1/export/sigma`)
- **Nginx Watcher** — Bağımlılık gerektirmeyen Python ajanı; nginx erişim loglarından 404/auth/rate flood ve exploit imzalarını tespit eder
- **Fail2ban Entegrasyonu** — Otomatik ban olayı raporlama
- **MISP Resmi Feed** — STIX-uyumlu JSON feed, MISP ekosistemine kabul edildi
- **TAXII 2.1 Sunucusu** — Kurumsal SIEM/SOAR entegrasyonu için standart protokol (Anomali, ThreatConnect, CERT platformları)
- **Delta / Artımlı Feed** — Bant genişliğini azaltmak için `?since=` parametresi ve ETag desteği
- **ASN Kötüye Kullanım Bildirimi** — Ağ operatörlerine otomatik haftalık kötüye kullanım raporları (Shadowserver modeli)
- **AbuseIPDB / OTX / Spamhaus Raporlama** — Küresel tehdit veritabanlarına aktif katkı
- **IP & Alan Adı Yaşlandırma** — Aktif olmayan IP'ler için otomatik skor azaltma ve listeden çıkarma; ölü alan adları aktif izlemeden düşer
- **Topluluk Engelleme Listeleri** — TXT, JSON, CIDR, FortiGate CLI, iptables, Suricata kuralları, Wazuh CDB formatları
- **CVE Feed** — Satıcı bazlı filtrelenmiş RSS ile 1.600+ CISA KEV kaydı
- **BGP / IP Sorgulama** — ASN, GeoIP, tehdit skoru, kaynak atfı
- **STIX 2.1 Çıktısı** — Makine tarafından okunabilir tehdit istihbaratı paketi
- **IP Listeden Çıkarma** — Cloudflare Turnstile korumalı yanlış pozitif bildirimi
- **TR/EN İki Dilli** — Tam Türkçe ve İngilizce arayüz
- **Tehdit Raporları** — Yeni tespit analiziyle periyodik tehdit istihbaratı raporları

---

## Mimari

```
┌──────────────────────────────────────────────────────────────────┐
│                          Veri Kaynakları                          │
│  FortiGate Webhook │ HoneypotKapan │ Nginx Watcher │ Fail2ban    │
│  CT Log İzleme (Phishing) │ Feodo │ URLhaus │ ET │ CISA KEV      │
│  USOM Alan Adı Feed'i                                             │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                ┌──────────▼──────────┐
                │  SiberKapan Çekirdek│
                │  Tespit Motoru      │
                │  GeoIP Zenginleştirme│
                │  IP Azaltma Motoru  │
                │  Alan Adı Canlılık  │
                │  Katmanlama Motoru  │
                └──────────┬──────────┘
                           │
      ┌────────────────────┼────────────────────┐
      │                    │                    │
 ┌────▼────┐         ┌─────▼────┐        ┌─────▼──────┐
 │REST API │         │ TAXII    │        │  Raporlama  │
 │STIX 2.1 │         │ 2.1      │        │  AbuseIPDB  │
 │Delta    │         │ MISP     │        │  OTX        │
 │Suricata │         │ Feed     │        │  Spamhaus   │
 │Wazuh    │         │          │        │  ASN Bildirim│
 │Sigma    │         │          │        │             │
 └─────────┘         └──────────┘        └────────────┘
```

---

## Hızlı Başlangıç — FortiGate Entegrasyonu

SiberKapan'ı FortiGate'e 5 dakikada ekleyin:

**1. Automation Action (Webhook) Oluştur**

```
Name: SiberKapan
Protocol: HTTPS
URL: https://siberkapan.org/feed/fortigate
Method: POST
Header: X-SiberKapan-Key: <your-api-key>
Header: Content-Type: application/json
```

**HTTP Gövdesi:**
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

**2. Automation Stitch Oluştur**
- Trigger: `IPS Event` veya `Anomaly Logs`
- Action: Yukarıdaki webhook action'ı

**3. API Anahtarı Talep Et**
[siberkapan.org/iletisim](https://siberkapan.org/iletisim) üzerinden iletişime geçin

---

## Hızlı Başlangıç — Honeypot & Nginx Watcher

| Ajan | Ne Tespit Eder | Kurulum |
|-------|-----------------|---------|
| [HoneypotKapan](honeypot/) | SSH, RDP, FTP, Telnet, SMB, MySQL, MSSQL, VNC, HTTP, SIP, SMTP | `wget https://siberkapan.org/honeypot/install.py && sudo python3 install.py` |
| [Nginx Watcher](nginx-watcher/) | 404/auth/rate flood, exploit path imzaları, tarayıcı UA'ları | `curl -fsSL https://siberkapan.org/nginx-watcher/install.sh \| sudo bash -s -- --key=YOUR_KEY` |

---

## Oltalama & Zararlı Alan Adı Tespiti

SiberKapan, oltalama ve zararlı alan adlarını — çoğu zaman USOM gibi resmi listelerin hiç haberi olmadan — gerçek zamanlı yakalayan özel bir motor çalıştırır. Bu motor şunları birleştirir:

- **Certificate Transparency log izleme** — her yeni TLS sertifikası, yayınlandığı anda gözlemlenir
- **Marka & niyet kelimesi eşleştirme** — taklit edilen kurumların ve yaygın tuzak dilinin sınır-farkında tespiti
- **Bulanık (fuzzy) typosquat tespiti** — marka isimlerinin yakın-yanlış yazımlarını yakalar
- **Punycode/IDN çözümleme** ve **bulut altyapı filtreleme** ile gürültü azaltma
- **Kademeli DNS/HTTP canlılık doğrulaması** ile feed'in bayat, uzun süredir ölü alan adlarından arındırılması

Tespit pipeline'ının tam anlatımı: **[docs/PHISHING_DETECTION.md](docs/PHISHING_DETECTION.md)**

Kelime/pattern kütüphanesini genişletmeye katkı sağlamak ister misiniz? Bkz. **[docs/CONTRIBUTING_PATTERNS.md](docs/CONTRIBUTING_PATTERNS.md)**.

### Alan Adı Feed Uç Noktaları

| Uç Nokta | Açıklama |
|----------|-------------|
| `/domains/txt` \| `/domains/json` | Birleşik alan adı feed'i (USOM + kendi kaynaklı), `source`/`type`/`min_criticality` ile filtrelenebilir |
| `/domains/siberkapan/txt` \| `/domains/siberkapan/json` | Sadece kendi kaynaklı tespitler (CT-log + honeypot kaynaklı) |
| `/domains/usom-live/txt` \| `/domains/usom-live/json` | USOM listesinin, SiberKapan'ın hâlâ DNS-aktif olduğunu doğruladığı alan adlarıyla filtrelenmiş hali |

---

## API Referansı

### Feed Uç Noktaları (Delta/ETag destekli)

| Uç Nokta | Format | Açıklama |
|----------|--------|-------------|
| `/api/v1/view/all-feed` | TXT | Tüm kaynaklar birleşik — `?since=` destekler |
| `/api/v1/view/fortigate-feed` | TXT | FortiGate topluluk feed'i — `?since=` destekler |
| `/api/v1/view/honeypot-feed` | TXT | HoneypotKapan feed'i — `?since=` destekler |
| `/api/v1/view/nginx-feed` | TXT | Nginx Watcher feed'i — `?since=` destekler |

**Delta çekme örneği:**
```bash
# Belirli bir zaman damgasından sonra eklenen IP'ler
curl "https://siberkapan.org/api/v1/view/all-feed?since=2026-07-01T00:00:00Z"

# ETag tabanlı önbellekleme (değişmediyse 304 döner)
curl -H "If-None-Match: \"sk-abc123\"" https://siberkapan.org/api/v1/view/all-feed
```

### Engelleme Listesi Export Uç Noktaları

| Uç Nokta | Format | Açıklama |
|----------|--------|-------------|
| `/api/v1/list/txt` | TXT | Tüm onaylı IP'ler, düz metin |
| `/api/v1/list/json` | JSON | Meta veriyle tam IP verisi |
| `/api/v1/list/cidr` | CIDR | CIDR notasyonu |
| `/api/v1/list/fortigate` | TXT | FortiGate CLI formatı |
| `/api/v1/list/iptables` | SH | iptables bash script |
| `/api/v1/export/suricata` | rules | Suricata IDS drop/alert kuralları |
| `/api/v1/export/wazuh-cdb` | CDB | Wazuh SIEM CDB listesi |
| `/api/v1/export/sigma` | YAML | Sigma tespit kuralı (SIEM-bağımsız) |

**Suricata entegrasyonu:**
```bash
curl -o /etc/suricata/rules/siberkapan.rules \
  "https://siberkapan.org/api/v1/export/suricata?min_score=75"
```

**Wazuh entegrasyonu:**
```bash
curl -o /var/ossec/etc/lists/siberkapan-blocklist \
  "https://siberkapan.org/api/v1/export/wazuh-cdb?min_score=75"
```

**Sigma entegrasyonu:**
```bash
curl -o siberkapan.yml "https://siberkapan.org/api/v1/export/sigma?min_score=40"
```

### TAXII 2.1 Uç Noktaları

| Uç Nokta | Açıklama |
|----------|-------------|
| `/taxii/` | Discovery |
| `/taxii/api-root/` | API Root |
| `/taxii/api-root/collections/` | Koleksiyon listesi |
| `/taxii/api-root/collections/{id}/objects/` | STIX objeleri (`added_after` destekler) |
| `/taxii/api-root/collections/{id}/manifest/` | Obje manifest'i |

**Koleksiyonlar:**

| ID | İsim | Açıklama |
|----|------|-------------|
| `a1b2c3d4-0001-4000-8000-siberkapan01` | Tüm Tehditler | Tüm onaylı IP'ler |
| `a1b2c3d4-0002-4000-8000-siberkapan02` | Yüksek Risk | Skor 75+ |
| `a1b2c3d4-0003-4000-8000-siberkapan03` | Honeypot | Honeypot tespitleri |

```bash
# TAXII discovery
curl -H "Accept: application/taxii+json;version=2.1" https://siberkapan.org/taxii/

# STIX objelerini çek
curl "https://siberkapan.org/taxii/api-root/collections/a1b2c3d4-0001-4000-8000-siberkapan01/objects/?limit=100"
```

### MISP Feed

```
https://siberkapan.org/misp-feed/manifest.json
```

MISP'e ekle: Administration → Feeds → Add Feed → URL: `https://siberkapan.org/misp-feed/`

### CVE / Tehdit İstihbaratı

| Uç Nokta | Açıklama |
|----------|-------------|
| `/api/v1/cve` | CISA KEV CVE kayıtları (JSON) |
| `/api/v1/cve?vendor=fortinet` | Satıcıya göre filtrelenmiş CVE'ler |
| `/rss/cve` | CVE RSS feed |
| `/rss/ioc` | IOC RSS feed |
| `/api/v1/stix` | STIX 2.1 paketi |
| `/api/v1/bgp/{ip}` | IP itibar & BGP sorgulama |
| `/api/v1/ip/{ip}` | IP tehdit istihbaratı sorgulama (JSON) |
| `/api/v1/status` | Platform durumu |

---

## Tehdit Skorlama

| Kaynak | Skor Artışı | Not |
|--------|-----------|-------|
| FortiGate — Kritik | +40 | Doğrulanmış API anahtarı, kritik önem |
| FortiGate — Yüksek | +30 | Doğrulanmış API anahtarı, yüksek önem |
| FortiGate — Orta | +20 | Doğrulanmış API anahtarı, orta önem |
| FortiGate — Düşük | +10 | Doğrulanmış API anahtarı, düşük önem |
| Dış Feed | 50 | Başlangıç skoru, kaynağa bağlı |
| Toplu API | +15 | Toplu gönderim |

Skorlar kümülatiftir (maks. 100). IP'ler 30 günlük hareketsizlikten sonra günde -2 puan azalır ve skor 15'in altına düştüğünde otomatik olarak listeden çıkarılır.

---

## Veri Kaynakları

| Kaynak | Tip | Güncelleme |
|--------|------|--------|
| FortiGate Topluluk Webhook'ları | Topluluk | Gerçek zamanlı |
| HoneypotKapan Sensörleri | Topluluk | Gerçek zamanlı |
| Nginx Watcher Ajanları | Topluluk | Gerçek zamanlı |
| Fail2ban Raporları | Topluluk | Gerçek zamanlı |
| Certificate Transparency Logları (Phishing) | Kendi kaynaklı | Gerçek zamanlı |
| [USOM Alan Adı Listesi](https://siberguvenlik.gov.tr) | Dış | Saatlik |
| [Feodo Tracker](https://feodotracker.abuse.ch) | Dış | 6s |
| [URLhaus](https://urlhaus.abuse.ch) | Dış | 6s |
| [Emerging Threats](https://rules.emergingthreats.net) | Dış | 12s |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE | Günlük |
| [RIPE NCC](https://stat.ripe.net) | Ülke Prefiksleri | Talep üzerine |

---

## Güvenlik & Veri Kalitesi

Bir tehdit istihbaratı platformu kurmak, veri bütünlüğü, yanlış pozitifler ve düşmanca manipülasyon konusunda kendine özgü zorluklar getirir. SiberKapan bunları sistematik olarak ele alır:

### IP Yaşlandırma & Otomatik Listeden Çıkarma

Tehdit skorları kalıcı değildir. Üç ay önce bir botnet'in parçası olan bir IP, meşru bir kullanıcıya yeniden atanmış olabilir. SiberKapan, AbuseIPDB'nin kendi skorlama felsefesini model alan zaman tabanlı bir azaltma mekanizması uygular:

- **Koruma süresi:** Son 30 gün içinde aktivite gösteren IP'ler azaltmadan korunur
- **Günlük azaltma:** Koruma süresinden sonra tehdit skoru günde 2 puan azalır
- **Otomatik listeden çıkarma:** Skor 15'in altına düştüğünde IP tüm feed ve engelleme listelerinden çıkarılır — ancak denetim amacıyla kayıt saklanır
- **Doğal sıfırlama:** Herhangi bir yeni tespit azaltma sayacını sıfırlar, kalıcı tehditlerin erken listeden çıkmasını önler
- **Uygulama:** Azaltma, satır satır güncelleme yerine toplu bir işlem olarak çalışır, eşzamanlı yük altında kilit çakışmasını önler

### Yanlış Pozitif Önleme

**Altyapı beyaz listesi:** CDN ve bulut proxy altyapısı (Cloudflare, Fastly, AWS CloudFront, Google) tehdit feed'lerinden otomatik olarak hariç tutulur. İzlenen bir web sunucusunun önünde bir reverse proxy varsa, saf log analizi proxy'nin edge node'larını saldırgan olarak işaretler. SiberKapan bunu, tespit edilen IP'leri her sağlayıcının resmi yayınlanmış CIDR aralıklarıyla çapraz referanslayarak çözer — 24 saatte bir güncellenir. Altyapı olarak tanımlanan IP'ler etiketlenir ve feed'lerden, yeni tespit hesaplamalarından ve AbuseIPDB raporlamasından hariç tutulur.

**UDP sahtecilik koruması:** UDP bağlantıları, protokolün bağlantısız doğası ve kaynak adres sahteciliğinin mümkün olması nedeniyle doğrulanmış bir kaynak IP'ye atfedilemez. Tüm sadece-UDP tespitleri (UDP flood, UDP tarama, oturum tabanlı UDP anomalileri) dahili trafik analizi için saklanır ancak şunlardan açıkça hariç tutulur:
- Tüm public feed uç noktaları
- AbuseIPDB gönderimleri
- MISP feed olayları
- ASN kötüye kullanım bildirimleri

Bu, aynı sahtecilik endişeleri nedeniyle UDP tabanlı gönderimleri açıkça yasaklayan AbuseIPDB'nin kendi raporlama politikasıyla tutarlıdır. Hariç tutma, bir UI filtresi olarak değil, veri pipeline seviyesinde uygulanır — yani sadece-UDP IP'ler, gönderim nasıl tetiklenirse tetiklensin hiçbir dış raporlama kanalına ulaşamaz.

**Yeni tespit metodolojisi:** Platformun "yeni tespit" metriği (daha önce AbuseIPDB'ye bilinmeyen IP yüzdesi) sadece organik olarak tespit edilen IP'lere göre hesaplanır — honeypot, FortiGate, Nginx Watcher ve Fail2ban kaynakları. Dış feed toplamları (Feodo Tracker, URLhaus, Emerging Threats) zaten bilinen küresel tehditlerden oluştuğu ve metriği yapay olarak düşüreceği için bu hesaplamaya dahil edilmez.

**Oltalama tespit güvenceleri:** Tüm sinyali bulanık (fuzzy) kaynaklı olan alan adı tespitleri (tam marka veya niyet eşleşmesi olmayan) otomatik onay eşiğinin altında sabitlenir ve manuel incelemeye yönlendirilir — rastlantısal alt-dize çakışmalarının denetimsiz şekilde public feed'lere ulaşması önlenir. Detaylar için bkz. [docs/PHISHING_DETECTION.md](docs/PHISHING_DETECTION.md).

### Veri Zehirlenmesi & Kötüye Kullanım Önleme

**Kaynak doğrulama:** FortiGate webhook gönderimleri önceden verilmiş bir API anahtarı gerektirir. Anahtar belirli bir katkıcı hesabına bağlıdır ve tespitleri doğrulanmış bir sensöre atfetmek için kullanılır. Anahtarsız gönderimler reddedilir.

**Özel IP reddi:** RFC 1918 özel adres alanı (10.x.x.x, 172.16.x.x, 192.168.x.x) ve loopback adresleri, ingestion katmanında reddedilir. Bunlar gerçek dış tehditleri temsil edemez ve topluluk engelleme listelerini zehirlemek için yaygın bir vektördür.

**Doğrulamalı listeden çıkarma:** Listeden çıkarma talepleri geçerli bir e-posta adresi gerektirir, Cloudflare Turnstile bot tespitinden geçer ve gönderen başına 24 saatte 3 talep ile sınırlıdır. Tüm talepler manuel olarak incelenir; onaylanan listeden çıkarmalar denetim amacıyla kaydedilir.

**Çoklu kaynak doğrulaması:** Birden fazla bağımsız kaynak tarafından tespit edilen bir IP (örn. hem farklı organizasyonlardan bir honeypot hem bir FortiGate sensörü) daha yüksek güven skoru alır. Tek kaynaklı tespitler muhafazakar şekilde skorlanır.

### Malware Örnek İşleme

SiberKapan'ın SSH honeypot'u, saldırganların indirmeye çalıştığı malware örneklerini asla depolamadan veya çalıştırmadan yakalar:

- **SSRF koruması:** İndirme URL'sinin hostname'i çözümlenir ve döndürülen her adres, herhangi bir bağlantı yapılmadan önce genel (public) bir IP olarak doğrulanır — özel, loopback, link-local ve bulut-metadata adresleri reddedilir. Doğrulanan IP'ye doğrudan bağlanılır (yeniden çözümlenmez), bu da DNS-rebinding bypass'ını önler.
- **Kalıcılık yok:** Dosya akış halinde okunur, hashlenir (SHA256) ve atılır — asla diske yazılmaz ve asla çalıştırılmaz.
- **Sınırlı çekme:** 5MB boyut sınırı, 8 saniye timeout, maksimum 3 yönlendirme (her biri ayrı ayrı yeniden doğrulanır).
- **Zenginleştirme, depolama değil:** Yakalanan hash'ler, SiberKapan dosyayı hiç barındırmadan bilinen malware ailelerini tanımlamak için [MalwareBazaar](https://bazaar.abuse.ch) ile kontrol edilir.

---

- **Standartlar:** STIX 2.1, TAXII 2.1, RSS/Atom, REST
- **Entegrasyonlar:** MISP, AbuseIPDB, AlienVault OTX, Spamhaus, Suricata, Wazuh

---

## Tehdit Raporları

Tespit eğilimlerini, yeni tehdit keşif oranlarını ve saldırı pattern analizini inceleyen periyodik tehdit istihbaratı raporları.

- [Sayı 1 — Haziran–Temmuz 2026](https://siberkapan.org/tehdit-raporlari/sayi-1) | [EN PDF](https://siberkapan.org/static/reports/siberkapan-tehdit-raporu-sayi1-en.pdf) | [TR PDF](https://siberkapan.org/static/reports/siberkapan-tehdit-raporu-sayi1-tr.pdf)

---

## IP Listeden Çıkarma

IP'nizin yanlışlıkla listelendiğini düşünüyorsanız:
👉 [https://siberkapan.org/delist](https://siberkapan.org/delist)

Her talep 48 saat içinde incelenir. Cloudflare Turnstile ile bot koruması.

---

## Lisans

MIT License — detaylar için bkz. [LICENSE](LICENSE).

---

## İletişim

- **Platform:** [siberkapan.org](https://siberkapan.org)
- **İletişim Formu:** [siberkapan.org/iletisim](https://siberkapan.org/iletisim)
- **Geliştirici:** [Oktay ALVER](https://www.linkedin.com/in/oktayalver/)
