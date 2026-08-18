# django-bouncer

**Django için ikinci savunma hattı — IP yasağı, WAF imzaları, bot sınıflandırma, honeypot ve hız sınırı; hepsi "korumaya çalıştığın insanı asla dışarıda bırakma" ilkesiyle yazıldı.**

[![CI](https://github.com/ahmet6141/django-bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmet6141/django-bouncer/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Django 4.2+](https://img.shields.io/badge/django-4.2%20%7C%205.x-092E20)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

🇬🇧 [English README](README.md)

---

Sitenin önündeki CDN birinci savunma hattıdır ve iyi bir hattır. Ama her zaman açık
değildir, her zaman haklı değildir ve senin URL'lerini bilmez: `/cart/apply-discount/`
uçunun dakikada 15, `/api/` uçunun 240 istek hak ettiğini bilemez — ve bir ziyaretçinin
**neden** artık giriş yapamadığını sana söyleyemez.

django-bouncer bunun altındaki katman. Yedi küçük middleware, iki tablo, dört yönetim
komutu — ve bir adresin ne zaman yasaklanabileceğine dair, naif bir sürümün gerçek
müşterileri yasakladığı görüldükten sonra yazılmış kurallar.

## Bu paketin asıl derdi

Saldırıyı engelleyen kural yazmak kolay. Saldırıyı engelleyip **aynı anda** mobil
kullanıcıyı engellememek zor olan kısım; ev yapımı güvenlik katmanlarının sessizce
battığı yer de tam burası:

| Tuzak | django-bouncer ne yapıyor |
|---|---|
| Tek bir `/wp-login.php` denemesi adresi yasaklıyor | Deneme 404 alır. **Yasak** için 10 dakikada **3 farklı** tarayıcı yolu gerekir — gerçek tarayıcılar sıralar, meraklı insan sıralamaz. |
| `drop table lamp` araması WAF'a takılıyor | İmzalar doğal dile asla eşleşmez. Test paketinde 90+ masum metnin geçtiği doğrulanır. |
| CGNAT adresini yasaklamak bütün mahalleyi kesiyor | Giriş yapmış kullanıcı "yumuşak" sinyaller (WAF, hız sınırı) yüzünden asla IP-yasaklanmaz. Hesap izlenebilir, paylaşılan adres değil. |
| UA'da `curl` görünce ofisin adresi yasaklanıyor | User-Agent tespitleri **hiçbir zaman** global yasak üretmez. İstek reddedilir; sürekli kötüye kullanımı hacim yakalar. |
| 5xx fırtınası saldırı gibi görünüyor | Hız sınırı ihlali her istek için değil, dakika başına bir kez sayılır. |
| Kendi adresini yasakladın | Giriş yap: staff girişi yasağı kaldırır ve adresi bir hafta güvenilir yapar. Geçici yasaklarda giriş sayfasının açık kalmasının tek sebebi budur. |
| Forwarded başlığına körü körüne güveniliyor | İstemci adresi, açıkça beyan edilmiş proxy sayısından çözülür ve zincir beklenenden kısaysa soket adresine **kapanır**. |
| Açmak bir inanç sıçraması | `BOUNCER_MODE=observe` her şeyi tespit edip kaydeder, hiçbir şeyi engellemez. Yasaklar iki ayrı anahtarla, varsayılan olarak kapalıdır. |

## Kutunun içinde ne var

Çalışma sırasıyla middleware'ler:

| Middleware | Ne yapar | Yasaklayabilir mi? |
|---|---|---|
| `ClientIPMiddleware` | Güvenilir istemci adresini bir kez çözer, `request.bouncer_ip` olarak yayınlar. | — |
| `IPBanMiddleware` | Yasaklı adrese 403, dakikada tek log. Geçici yasakta giriş sayfası açık kalır. | — |
| `HoneypotMiddleware` | `/wp-login.php`, `/.env`, `/phpmyadmin/` … → 404. Gizli form alanı doluysa → 403. | 10 dk'da 3 farklı yol → 30 dk |
| `JSONRequestValidationMiddleware` | JSON gövdesini sınırlar ve ayrıştırır; `request.json_body` verir. | — |
| `WAFMiddleware` | Decode edilmiş URL/query/gövdede yüksek-güvenli SQLi / XSS / traversal / komut enjeksiyonu imzaları. | 10 dk'da ≥2 uçta 5 olay → 60 dk |
| `BotDetectorMiddleware` | Tarayıcı araçlarını, HTTP kütüphanelerini, headless tarayıcıları ve boş UA'ları sınıflar; iyi botları serbest bırakır. | **asla** |
| `RateLimitMiddleware` | Yol öneki bazında adres başına dakika limiti + kaba kuvvet giriş kilidi. | 10 dk'da 5 ihlal dakikası → 15 dk |

Ayrıca: admin'de denetim kaydı ve yasak listesi, dört operasyon komutu ve bu tür
paketlerin genelde sessizce yanlış yapılandırıldığı noktaları yakalayan açılış
kontrolleri.

## Kurulum

```bash
pip install git+https://github.com/ahmet6141/django-bouncer.git
```

```python
# settings.py
INSTALLED_APPS = [..., "django_bouncer"]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # ── django-bouncer ──
    "django_bouncer.middleware.ClientIPMiddleware",
    "django_bouncer.middleware.IPBanMiddleware",
    "django_bouncer.middleware.HoneypotMiddleware",
    "django_bouncer.middleware.JSONRequestValidationMiddleware",
    "django_bouncer.middleware.WAFMiddleware",
    "django_bouncer.middleware.BotDetectorMiddleware",
    "django_bouncer.middleware.RateLimitMiddleware",
    # ───────────────────
    "django.contrib.sessions.middleware.SessionMiddleware",
    ...
]
```

```bash
python manage.py migrate
python manage.py check --deploy      # sadece Django ayarlarını değil, bu kurulumu da doğrular
python manage.py bouncer_status      # gerçekte yürürlükte olan yapılandırmayı basar
```

Her şeyden önce doğru ayarlanması gereken üç ayar:

```python
# SENİN işlettiğin proxy sayısı — X-Forwarded-For'un sağından sayılır.
# 0 (varsayılan) forwarded başlıklarını tamamen yok sayar. Başlığı yeniden
# yazan bir nginx 1'dir; önünde Cloudflare olsa bile yine 1.
BOUNCER_TRUSTED_PROXY_COUNT = 1

# Kendi imza doğrulaması olan uçlar (ödeme callback'i, webhook).
# Boş ya da kütüphane UA'sıyla gelirler; birini kesmek ödeme onayını kaybettirir.
BOUNCER_EXEMPT_PATHS = "/payments/callback/,/webhooks/"

# Senin adresin ve asla dokunulmaması gereken her şey.
BOUNCER_TRUSTED_IPS = "203.0.113.7,10.0.0.0/8"
```

Her ayar aynı isimle ortam değişkeninden de okunabilir; böylece bir operatör deploy
beklemeden, yalnız restart ile limit gevşetebilir. Tam liste:
**[docs/SETTINGS.md](docs/SETTINGS.md)**.

## Siteyi kırmadan devreye alma

Varsayılanlar zaten temkinli — sen söylemeden hiçbir şey yasaklanmaz — ama dürüst sıra
şudur:

```bash
# 1. İzle. Her şey tespit edilir ve kaydedilir, hiçbir şey engellenmez.
BOUNCER_MODE=observe

# 2. Birkaç gün, ne engelleyecekmiş oku.
python manage.py bouncer_report --hours 72

# 3. İstek bazlı engellemeyi aç; hâlâ hiç yasak yok.
BOUNCER_MODE=enforce

# 4. Dedektörler yasak yazsın, ama yasaklar etkisiz kalsın (yalnız denetim).
BOUNCER_AUTO_BAN=1

# 5. Yasak listesi doğru görününce yasakları gerçekten uygula.
BOUNCER_BAN_ENFORCEMENT=1
```

Tek bir katman geride kalabilir — kendi imzalarını eklerken işine yarar:

```python
BOUNCER_LAYER_MODES = {"waf": "observe"}   # ya da "off"
```

## Bir şey engellendiğinde sebebini görmek

```console
$ python manage.py bouncer_report --ip 203.0.113.44

--- 203.0.113.44 ---
BannedIP: active=True reason=scanner_path hits=3 expires=2026-08-18 17:40 ...

Last 6 event(s):
  08-18 16:58:11 BLOCK honeypot_url    GET   /wp-login.php    /wp-login.php
  08-18 16:58:12 BLOCK honeypot_url    GET   /.env            /.env
  08-18 16:58:14 BLOCK honeypot_url    GET   /phpmyadmin/     /phpmyadmin
```

Dördü de canlıda çalıştırılabilir komutlar:

| Komut | Ne için |
|---|---|
| `bouncer_status [--json]` | Bu süreçte şu anda hangi yapılandırma yürürlükte. |
| `bouncer_report [--ip X] [--hours N]` | Bir adres neden engellendi; genel olarak ne oluyor. |
| `bouncer_unban <ip> [--trust]` | Admin'e erişemiyorken kabuktan kurtarma. |
| `bouncer_prune [--days N] [--dry-run]` | Saklama süresi. Denetim tablosu sürekli büyür; cron'dan çalıştır. |

Kendini kilitlediysen, kolaydan zora: **giriş yap** (staff girişi o adresin yasağını
kaldırır ve bir hafta güvenilir yapar) → admin → *Banned IPs* → "yasağı kaldır + güven"
→ SSH'tan `python manage.py bouncer_unban <ip> --trust`.

## Açılış kontrolleri

`manage.py check`, aksi hâlde haftalar sonra anlaşılmaz davranış olarak ortaya çıkacak
hataları baştan söyler:

- middleware eksik ya da işlevini bozan bir sırada (`bouncer.E001`, `E002`);
- ayrıştırılamayan güvenilir adres / mod / katman adı / hız kuralı — hepsi normalde
  sessizce yok sayılırdı (`E003`–`E006`);
- `DummyCache` (hiçbir sayaç çalışmaz) veya `LocMemCache` (her worker ayrı sayar, gerçek
  limit = limit × worker sayısı) (`W002`, `W003`);
- yasak yazımı açıkken uygulama kapalı, ya da uygulama açıkken geri dönüş yolu yok
  (`W005`, `W006`);
- yalnız `--deploy`: proxy arkasında olup proxy sayısı 0 — tüm ziyaretçilerin tek kovaya
  düştüğü ve tek yasağın herkesi vurduğu durum (`W008`).

## Honeypot form alanı

```django
{% load bouncer %}
<form method="post">{% csrf_token %}
  ...
  {% bouncer_honeypot %}
</form>
```

Tarayıcı otomatik doldurmasının tetiklemeyeceği, projene özgü bir ad ver:

```python
BOUNCER_HONEYPOT_FIELD_NAME = "acme_hp_check"
```

## Bu paketin bilerek yapmadıkları

- **CDN/WAF'ın yerine geçmez.** Senin URL'lerini bilen katman odur.
- **CAPTCHA, JS challenge, fingerprint yapmaz.** Bunlar frontend sözleşmesi ister; bu
  paket middleware'dir.
- **GeoIP engellemesi yapmaz.** Ülke, niyetin zayıf bir göstergesidir ve bu paketin
  taşımayacağı bir veritabanı gerektirir.
- **"Şüpheli davranış" konusunda akıllılık taslamaz.** Saniye-altı gezinme ve eksik
  tarayıcı başlıkları yalnız kaydedilir, asla engellenmez: sekme geri yükleme ve link
  prefetch aynı izi bırakır.

## Uyumluluk

Python 3.10–3.13 · Django 4.2, 5.0, 5.1, 5.2 · her cache arka ucu (canlıda Redis veya
Memcached; bkz. `bouncer.W003`) · Django'nun desteklediği her veritabanı.

İngilizce ve Türkçe paketle birlikte gelir; ziyaretçiye görünen sayfalar `gettext`
üzerinden geçer, yani yeni bir dil eklemek bir `.po` dosyasıdır.

## Testler

```bash
pip install -e ".[dev]"
pytest
```

344 test; veritabanı sunucusu ya da Redis gerekmez — bellek içi sqlite ve yerel cache.
Paket, bu README'deki iddiaların etrafında düzenlenmiştir: `test_ban_safety.py` yanlış-yasak
garantilerini gerçek veritabanına karşı doğrular, `test_signatures.py` sıradan metnin
eşleşmediğini iddia eder, `test_layer_modes.py` observe modunun enforce modunun
engellediğinin aynısını tespit ettiğini kontrol eder.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
