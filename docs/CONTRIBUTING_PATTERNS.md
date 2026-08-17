# SiberKapan Phishing Pattern Listesine Katkı / Contributing to Phishing Patterns

## 🇹🇷 Türkçe

`phishing_patterns.json` dosyası, SiberKapan'ın oltalama alan adı tespit motorunun kullandığı marka, kurum ve niyet kelimelerini içerir. Bu liste ne kadar kapsamlı olursa, tespit oranımız da o kadar yükselir — bu yüzden topluluk katkısına açığız.

**Not:** Bu dosyadan skorlama ağırlıkları ve eşik değerleri bilinçli olarak çıkarılmıştır (bkz. `PHISHING_DETECTION.md`), çünkü bu değerlerin açık olması saldırganların tespiti bypass etmesini kolaylaştırır. Katkılar sadece **kelime listeleri** (brand_keywords, intent_keywords, suspicious_tlds, dynamic_dns_providers, action_keywords, whitelist_domains) için kabul edilmektedir.

### Nasıl katkı yapılır?

**Yöntem 1 — Issue açarak (kod bilmeyenler için, önerilen):**
1. Repo'da "Issues" sekmesine git
2. "New Issue" butonuna bas
3. Başlığa "Yeni pattern önerisi: [marka/kurum adı]" yaz
4. Açıklamaya şunları belirt:
   - Eklenmesini istediğin kelime(ler)
   - Hangi kategoriye ait olduğu (banka mı, kamu kurumu mu, e-ticaret mi, vb.)
   - Varsa, bu markayı taklit eden gerçek bir oltalama örneği (URL, ekran görüntüsü)
5. Ekibimiz inceleyip onaylarsa dosyaya ekleriz.

**Yöntem 2 — Pull Request ile (GitHub'a aşinaysanız):**
1. Repo'yu fork'la
2. `phishing_patterns.json` dosyasında ilgili kategoriye kelimeni ekle (sadece kelime listelerine — `whitelist_domains`'e de yanlışlıkla eklenmemesi için markanın **resmi** alan adını da eklemeyi unutma)
3. Değişikliği neden önerdiğini açıklayan bir PR aç
4. İnceleme sonrası merge edilir

### Neyi kabul ediyoruz, neyi etmiyoruz?

- ✅ Gerçekten hedef alınan (phishing kurbanı olmuş/olabilecek) Türkiye merkezli banka, kamu kurumu, e-ticaret, telekom, kargo, fintech markaları
- ✅ Bu markaların **resmi/doğrulanmış** alan adları (whitelist için)
- ✅ Yaygın oltalama sayfalarında görülen eylem/niyet kelimeleri
- ❌ Rastgele/spekülatif kelime önerileri (kanıt olmadan)
- ❌ Skorlama ağırlığı veya eşik değeri değişiklik talepleri (bu değerler açık kaynağa alınmıyor)

---

## 🇬🇧 English

`phishing_patterns.json` contains the brand, institution, and intent keywords used by SiberKapan's phishing domain detection engine. The more complete this list is, the better our detection rate — so we welcome community contributions.

**Note:** Scoring weights and auto-approve thresholds are intentionally excluded from this file (see `PHISHING_DETECTION.md`), since publishing them would make it easier for attackers to evade detection. Contributions are accepted only for **keyword lists** (brand_keywords, intent_keywords, suspicious_tlds, dynamic_dns_providers, action_keywords, whitelist_domains).

### How to contribute

**Option 1 — Open an Issue (recommended for non-developers):**
1. Go to the "Issues" tab on the repo
2. Click "New Issue"
3. Title it "New pattern suggestion: [brand/institution name]"
4. In the description, include:
   - The word(s) you'd like added
   - Which category it belongs to (bank, government, e-commerce, etc.)
   - If available, a real phishing example impersonating this brand (URL, screenshot)
5. We'll review and add it if approved.

**Option 2 — Pull Request (if you're familiar with GitHub):**
1. Fork the repo
2. Add your keyword to the relevant category in `phishing_patterns.json` (keyword lists only — if adding a brand, also consider adding its **official** domain to `whitelist_domains`)
3. Open a PR explaining why you're proposing the change
4. It'll be merged after review

### What we accept vs. don't

- ✅ Turkey-based banks, government bodies, e-commerce, telecom, shipping, or fintech brands that are genuinely being (or likely to be) targeted by phishing
- ✅ **Official/verified** domains for those brands (for the whitelist)
- ✅ Action/intent keywords commonly seen on phishing pages
- ❌ Random/speculative keyword suggestions with no supporting evidence
- ❌ Requests to change scoring weights or thresholds (these are intentionally kept out of the public repo)
