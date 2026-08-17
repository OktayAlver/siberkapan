# SiberKapan Phishing & Malicious Domain Detection Mechanism
## SiberKapan Oltalama (Phishing) ve Zararlı Alan Adı Tespit Mekanizması

---

## 🇹🇷 Türkçe

### Genel Bakış

SiberKapan'ın domain-level tehdit istihbaratı üç ayrı kaynaktan beslenir:

1. **usom-domains** — USOM'un açık API'sinden (siberguvenlik.gov.tr) saatlik delta-sync ile alınan resmi liste (480K+ kayıt)
2. **honeypot-domains** — kendi SSH honeypot ağımızın yakaladığı, saldırganların indirmeye çalıştığı malware C2/dağıtım alan adları
3. **phishing-domains** — kendi geliştirdiğimiz, gerçek zamanlı **Certificate Transparency (CT) log izleme** motoru ile tespit edilen oltalama alan adları

Bu doküman özellikle üçüncü kaynağı, yani kendi phishing tespit motorumuzu anlatır.

### Neden CT Log İzleme?

USOM gibi resmi listeler **şikayet tabanlı (complaint-driven)** çalışır — bir alan adı ancak birileri şikayet ettikten sonra listeye girer. Bu da genelde saldırı zaten gerçekleştikten sonra olur.

CT log izleme ise farklı bir yaklaşım sunar: TLS sertifikası olan her yeni alan adı, sertifika yayınlandığı anda (genelde alan adı kayıt edilip aktif hale gelmeden önce) Certificate Transparency loglarına düşer. Biz bu logları gerçek zamanlı dinleyerek, USOM'un haberi bile olmadan yeni oltalama alan adlarını yakalayabiliyoruz.

**Kanıtlanmış örnek:** `garantibbvabankası.ph` alan adı, USOM listesinde hiç yer almadan SiberKapan tarafından tespit edildi — marka adı eşleşmesi (garantibbva) + alışılmadık `.ph` uzantısı kombinasyonuyla.

### Mimari: 3 Aşamalı Pipeline

```
CT Log WebSocket (certstream-server-go, self-hosted)
        │
        ▼
   scan_queue (thread 1: sadece veri alımı, hiç iş yapmaz)
        │
        ▼
   scan_worker (thread 2: skorlama + fuzzy matching)
        │
        ▼
   db_queue → db_worker (thread 3: veritabanı yazımı)
```

Bu ayrım kritik: ağır CPU işi (skorlama, fuzzy matching) hiçbir zaman veri alımını (ingestion) bloklamaz. Yoğun sertifika trafiğinde bile hiçbir kayıt kaçmaz.

### Tespit Yöntemleri

Bir alan adı şu katmanlardan geçerek puanlanır:

**1. Marka Adı Eşleşmesi (Brand Keyword Matching)**
Bilinen banka/kurum isimlerinin (örn. büyük Türk bankaları, kamu kurumları) alan adı içinde geçip geçmediği, sınır-farkında (boundary-aware) regex ile kontrol edilir. Kısa anahtar kelimeler (≤4 karakter) etrafında ayraç karakteri şart koşulurken, uzun kelimeler için alfabetik olmayan bir sınır yeterlidir. Bu, "ing" gibi kısa bir markanın "parking.com" gibi masum alan adlarında yanlış pozitif üretmesini engeller.

**2. Niyet Kelimesi Eşleşmesi (Intent Keyword Matching)**
Oltalama sayfalarında sık görülen kategori kelimeleri (bankacılık işlemleri, kamu hizmetleri, "güncelle/doğrula/aktivasyon" gibi eylem çağrıları) ayrı bir regex katmanıyla taranır.

**3. Fuzzy (Bulanık) Eşleşme**
SymSpell tarzı silme-tabanlı (deletion-based) indeksleme kullanılır — kelime uzunluğuyla orantılı hash lookup maliyeti, edit-distance ≤1 (tek karakter fark). Minimum kelime uzunluğu 5 karakter altına inmez (kısa kelimelerde fuzzy matching anlamsız gürültü üretir).

**4. Kombinasyon Bonusu**
Bir alan adında 2 veya daha fazla farklı kelime grubu (marka + niyet, ya da iki ayrı niyet kelimesi) eşleşirse ekstra puan verilir — tek başına zayıf sinyaller, birlikte güçlü sinyal oluşturur.

**5. Punycode / IDN Çözümleme**
Uluslararası alan adları (örn. Türkçe karakterli sahte alan adları) punycode formatından çözülerek gerçek görünümleriyle taranır — aksi halde `xn--` ile başlayan kodlanmış hallerinde kelime eşleşmesi hiç yakalanamaz.

**6. Bulut Sağlayıcı Filtresi**
`amazonaws.com`, `cloudfront.net`, `azurewebsites.net`, `googleusercontent.com` gibi meşru bulut altyapı alan adları, alt-domain yapıları nedeniyle yanlış pozitif üretmeye çok yatkın olduğundan ayrı bir filtre katmanıyla elenir.

### Yanlış Pozitif (False Positive) Önlemleri

Canlıya alındıktan sonra karşılaşılan ve düzeltilen gerçek vakalar:

- **Rastgele tekil fuzzy eşleşmeler:** Başlangıçta tek bir zayıf fuzzy eşleşme bile otomatik onaya yetiyordu (40 saniyede 750 eşleşme, 93 otomatik onay — çoğu alakasız global-dil alan adları). Çözüm: bonus puan almak için en az 2 farklı kelime grubu eşleşmesi (veya tam/exact eşleşme) şartı getirildi.
- **Rastlantısal çoklu-fuzzy çakışmaları:** `mistergift.fr` gibi bir alan adı, "ister"~"istek" ve "tergi"~"vergi" gibi iki alakasız İngilizce/Fransızca alt-dize parçasının rastlantısal olarak Türkçe kelimelere fuzzy-eşleşmesiyle yüksek puan alabiliyordu. Çözüm: bir alan adının puanı **tamamen** fuzzy-kaynaklıysa (hiç tam marka/niyet eşleşmesi yoksa), otomatik onay eşiğinin altında sabitlenir — yine incelemede görünür kalır ama denetimsiz şekilde MISP feed'ine sızamaz.
- **Provenance'ı belirsiz gürültü kaynağı kelimeler:** Kaynağı doğrulanamayan, en çok gürültü üreten anahtar kelimeler listeden tamamen çıkarıldı.

Bu iyileştirmeler sonucu ilk 160 civarı yanlış pozitiften, ayarlama sonrası neredeyse sıfıra inildi.

### Doğrulama (Liveness) Katmanı

Tespit edilen her alan adı, kademeli (tiered) bir DNS + HTTP canlılık kontrolünden geçer:
- Asenkron DNS taraması (eş zamanlı sorgu limiti ile)
- DNS aktif çıkan own-source alan adları için, DNS-rebinding saldırılarına karşı korumalı (pinned resolver) HTTP probu — TLS SNI/hostname doğrulaması korunarak
- Alan adları yaşlarına ve geçmiş kontrol sonuçlarına göre kademelere (tier0→tier3) ayrılır; ölü alan adları giderek daha seyrek kontrol edilir, aktif olanlar daha sık

Bu sayede hem USOM'un hiç temizlemediği "ölü" alan adlarını ayırt edebiliyoruz hem de kendi own-source feed'imizin her zaman güncel/canlı kalmasını sağlıyoruz.

### Sonuç

Bu motor, resmi/pasif listelerin (USOM dahil) yakalayamadığı, henüz kimsenin şikayet etmediği taze oltalama alan adlarını gerçek zamanlı yakalayabiliyor. Tespit edilen ve doğrulanmış (own-source, is_approved) alan adları hem SiberKapan'ın kendi domain feed'inde, hem de MISP default feed'inde yayınlanıyor.

---

## 🇬🇧 English

### Overview

SiberKapan's domain-level threat intelligence is fed by three independent sources:

1. **usom-domains** — Turkey's official USOM feed, bulk-imported and hourly delta-synced from their open API (480K+ records)
2. **honeypot-domains** — malware C2/download domains extracted directly from our own SSH honeypot network
3. **phishing-domains** — phishing domains detected in real time by our own **Certificate Transparency (CT) log monitoring** engine

This document focuses on the third source — our own phishing detection engine.

### Why CT Log Monitoring?

Official lists like USOM are **complaint-driven** — a domain only gets listed after someone reports it, usually after the attack has already happened.

CT log monitoring takes a different approach: any new domain that gets a TLS certificate appears in Certificate Transparency logs the moment the certificate is issued — often before the domain is even fully active. By streaming these logs in real time, we can catch new phishing domains before USOM (or anyone else) even knows they exist.

**Confirmed example:** `garantibbvabankası.ph` was detected by SiberKapan while completely absent from USOM's list — flagged via brand-name match (garantibbva) combined with an unusual `.ph` TLD.

### Architecture: 3-Stage Pipeline

```
CT Log WebSocket (self-hosted certstream-server-go)
        │
        ▼
   scan_queue (thread 1: ingestion only, no processing)
        │
        ▼
   scan_worker (thread 2: scoring + fuzzy matching)
        │
        ▼
   db_queue → db_worker (thread 3: database writes)
```

This separation matters: heavy CPU work (scoring, fuzzy matching) never blocks ingestion, so no certificate is missed even under heavy traffic.

### Detection Methods

Each domain is scored through the following layers:

**1. Brand Keyword Matching**
Known bank/institution names are checked against the domain using boundary-aware regex. Short keywords (≤4 chars) require a surrounding separator character; longer keywords only require a non-alphabetic boundary. This prevents short brand fragments (e.g. "ing") from false-triggering on innocent domains like "parking.com".

**2. Intent Keyword Matching**
Common phishing-page vocabulary (banking actions, public-service terms, "verify/update/activate"-style calls to action) is scanned via a separate regex layer.

**3. Fuzzy Matching**
A SymSpell-style deletion-index approach is used — hash lookup cost scales with word length, edit distance ≤1 (single character difference). Minimum word length is capped at 5 characters to avoid noisy short-word matches.

**4. Combo Bonus**
Domains matching 2+ distinct keyword groups (brand + intent, or two separate intent hits) receive a bonus — individually weak signals become a strong signal together.

**5. Punycode / IDN Decoding**
Internationalized domains (e.g. lookalike domains using non-Latin characters) are decoded from punycode before scanning — otherwise keyword matching would never trigger on their encoded `xn--` form.

**6. Cloud Provider Filter**
Legitimate cloud infrastructure domains (`amazonaws.com`, `cloudfront.net`, `azurewebsites.net`, `googleusercontent.com`, etc.) are filtered out separately, since their subdomain structures are especially prone to false positives.

### False Positive Mitigations

Real incidents found and fixed in production:

- **Isolated single fuzzy hits:** Initially, even one weak fuzzy match could auto-approve (750 matches in 40 seconds, 93 auto-approved — mostly unrelated foreign-language domains). Fixed by requiring 2+ distinct keyword-group hits (or one exact match) before any bonus is applied.
- **Coincidental multi-fuzzy collisions:** `mistergift.fr` scored high because two unrelated substrings ("ister"~"istek" and "tergi"~"vergi") each coincidentally fuzzy-matched different Turkish words. Fixed by hard-capping any detection whose *entire* signal is fuzzy-derived (no exact brand/intent match) below the auto-approve threshold — still visible for review, but never auto-approves unsupervised.
- **Unverified-provenance noise keywords:** Keywords with no clear source and the highest noise contribution were removed entirely.

These fixes brought false positives down from an initial ~160 to near-zero.

### Liveness Verification Layer

Every detected domain goes through a tiered DNS + HTTP liveness check:
- Asynchronous DNS sweep with bounded concurrency
- For own-source domains that transition to DNS-active, an SSRF/DNS-rebinding-safe HTTP probe (pinned resolver) — while still preserving correct TLS SNI/hostname verification
- Domains are grouped into tiers (tier0→tier3) based on age and check history; dead domains get checked less frequently, active ones more often

This lets us distinguish domains USOM never prunes (long-dead) from genuinely live threats, keeping our own-source feed consistently fresh.

### Summary

This engine catches fresh phishing domains in real time — before anyone has filed a complaint and before official lists like USOM even know they exist. Verified, own-source detections are published both on SiberKapan's dedicated domain feed and as part of the official MISP default feed.

---

*Related: [MISP default feed](https://siberkapan.org/misp-feed/) · [Domain feed](https://siberkapan.org/usom-domain-feed) · [Feed setup guide](https://siberkapan.org/feed-ekleme-rehberi)*
