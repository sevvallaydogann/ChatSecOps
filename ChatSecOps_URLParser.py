"""
ChatSecOps_URLParser.py - Otomatik Phishing URL Parçalama (Feature 1)
======================================================================
Mevcut ML modeli sadece domain üzerinde çalışır.
Bu modül URL'nin geri kalanını (path, query, subdomain yapısı)
analiz ederek bir "URL Risk Boost" skoru üretir.

Final skor = min(100, ML_skoru + URL_boost)

Akış:
  1. URL normalize et (hxxps, defanged, [.] notasyonu)
  2. urllib.parse ile bileşenlere ayır
  3. Her bileşen için kural tabanlı risk puanı hesapla
  4. Gerekçeli rapor üret
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Tuple


# =============================================================================
# KURAL TABANLI RİSK KURALLARI
# Her kural: (puan, açıklama)
# =============================================================================

# Path'te bulunan yüksek riskli anahtar kelimeler
PATH_HIGH_RISK_KEYWORDS = {
    "login":        (15, "Oturum açma sayfası taklidi"),
    "signin":       (15, "Giriş sayfası taklidi"),
    "sign-in":      (15, "Giriş sayfası taklidi"),
    "verify":       (15, "Doğrulama sayfası taklidi"),
    "verification": (15, "Doğrulama sayfası taklidi"),
    "secure":       (12, "Güvenlik sayfası taklidi"),
    "security":     (12, "Güvenlik sayfası taklidi"),
    "update":       (12, "Güncelleme sayfası taklidi"),
    "account":      (10, "Hesap sayfası taklidi"),
    "banking":      (18, "Bankacılık sayfası taklidi"),
    "bank":         (15, "Bankacılık sayfası taklidi"),
    "password":     (15, "Şifre sayfası taklidi"),
    "wallet":       (12, "Cüzdan sayfası taklidi"),
    "confirm":      (10, "Onay sayfası taklidi"),
    "recover":      (10, "Kurtarma sayfası taklidi"),
    "reset":        (10, "Sıfırlama sayfası taklidi"),
    "support":      (5,  "Destek sayfası taklidi"),
    "invoice":      (8,  "Fatura sayfası taklidi"),
    "payment":      (12, "Ödeme sayfası taklidi"),
    "checkout":     (8,  "Ödeme sayfası taklidi"),
}

# Path'te bulunan düşük-orta riskli kelimeler
PATH_MEDIUM_RISK_KEYWORDS = {
    "admin":        (8, "Admin paneli hedefli"),
    "wp-admin":     (8, "WordPress admin hedefli"),
    "webmail":      (6, "Webmail hedefli"),
    "cpanel":       (6, "cPanel hedefli"),
}

# Yönlendirme amaçlı query parametreleri — open redirect göstergesi
REDIRECT_PARAMS = {
    "redirect", "redirect_to", "redirect_url",
    "url", "goto", "next", "return",
    "returnurl", "return_url", "target",
    "destination", "dest", "forward", "redir",
    "link", "continue", "ref", "referer",
    "callback", "to", "from"
}

# Büyük markaların domain'leri — subdomain impersonation tespiti için
BRAND_DOMAINS = {
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "twitter", "linkedin", "netflix", "spotify",
    "dropbox", "github", "yahoo", "outlook", "hotmail", "gmail",
    "bankofamerica", "chase", "wells", "citibank", "hsbc",
    "garanti", "akbank", "isbank", "yapikredi", "ziraat",
    "steam", "valve", "blizzard", "epicgames",
    "dhl", "fedex", "ups", "tnt", "ptt"
}


class URLParser:
    """
    Phishing URL Analiz Motoru.
    
    Kullanım:
        parser = URLParser()
        result = parser.analyze("hxxps://paypal-security.tk/login?redirect=paypal.com")
        print(result["url_risk_boost"])   # 47
        print(result["findings"])         # Bulgular listesi
    """

    def normalize_url(self, raw_url: str) -> str:
        """
        Güvenlik raporlarında yaygın defanged (etkisizleştirilmiş) 
        URL formatlarını normalize eder.
        
        Örnekler:
          hxxps://example.com  → https://example.com
          hxxp://example[.]com → http://example.com
          example[.]com/path   → http://example.com/path
        """
        url = raw_url.strip()

        # hxxp / hxxps → http / https
        url = re.sub(r'^hxxps?://', lambda m: m.group(0).replace('hxxp', 'http'), url, flags=re.IGNORECASE)

        # [.] → .  (defanged nokta)
        url = url.replace("[.]", ".").replace("(.", ".").replace(".)", ".")

        # [:] → : (defanged iki nokta)
        url = url.replace("[:]", ":")

        # Şema yoksa ekle
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        return url

    def extract_domain_from_url(self, url: str) -> str:
        """
        URL'den sadece domain kısmını ayıklar.
        Mevcut ML modeline bu domain verilecek.
        
        https://paypal-security.tk/login → paypal-security.tk
        """
        try:
            parsed = urlparse(self.normalize_url(url))
            # www. ön ekini kaldır
            netloc = parsed.netloc.lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
            return netloc
        except:
            return url

    def _analyze_path(self, path: str) -> Tuple[int, List[str]]:
        """
        URL path'ini analiz eder.
        Döndürür: (toplam puan, bulgular listesi)
        """
        score = 0
        findings = []
        path_lower = path.lower()

        # Path tokenlarını ayır (/ ile)
        tokens = set(re.split(r'[/\-_.]', path_lower))
        tokens = {t for t in tokens if t}  # boşları temizle

        # Yüksek riskli kelimeler
        for keyword, (points, description) in PATH_HIGH_RISK_KEYWORDS.items():
            if keyword in tokens or keyword in path_lower:
                score += points
                findings.append(f"⚠️ Path'te '{keyword}' tespit edildi — {description} (+{points} puan)")
                break  # Aynı kategoriden birden fazla sayma

        # Orta riskli kelimeler
        for keyword, (points, description) in PATH_MEDIUM_RISK_KEYWORDS.items():
            if keyword in path_lower:
                score += points
                findings.append(f"ℹ️ Path'te '{keyword}' tespit edildi — {description} (+{points} puan)")

        # URL encoding şüphesi (aşırı encoded karakterler)
        encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', path))
        if encoded_count >= 3:
            score += 8
            findings.append(f"⚠️ Path'te {encoded_count} adet URL-encoded karakter — obfuscation şüphesi (+8 puan)")

        # Çok derin path (7+ seviye)
        depth = len([p for p in path.split('/') if p])
        if depth >= 7:
            score += 5
            findings.append(f"ℹ️ Çok derin path ({depth} seviye) — gizleme tekniği olabilir (+5 puan)")

        return min(score, 35), findings  # Path'ten max 35 puan

    def _analyze_query(self, query_string: str) -> Tuple[int, List[str]]:
        """
        Query string'i analiz eder.
        Döndürür: (toplam puan, bulgular listesi)
        """
        if not query_string:
            return 0, []

        score = 0
        findings = []
        params = parse_qs(query_string, keep_blank_values=True)
        param_keys_lower = {k.lower() for k in params.keys()}

        # Yönlendirme parametreleri
        redirect_found = param_keys_lower & REDIRECT_PARAMS
        if redirect_found:
            # Redirect değerinin kendisi de domain içeriyor mu?
            for key in params:
                if key.lower() in REDIRECT_PARAMS:
                    val = unquote(params[key][0]) if params[key] else ""
                    # Değer bir domain/URL mi?
                    if re.search(r'[a-z0-9\-]+\.[a-z]{2,}', val, re.IGNORECASE):
                        score += 20
                        findings.append(
                            f"🚨 Açık yönlendirme (Open Redirect): "
                            f"`?{key}={val}` — kullanıcıyı başka siteye yönlendiriyor (+20 puan)"
                        )
                    else:
                        score += 8
                        findings.append(
                            f"⚠️ Yönlendirme parametresi tespit edildi: `?{key}=` (+8 puan)"
                        )
                    break

        # Çok fazla query parametresi
        if len(params) >= 6:
            score += 5
            findings.append(f"ℹ️ {len(params)} query parametresi — anormal karmaşıklık (+5 puan)")

        # Query'de URL encoding
        encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', query_string))
        if encoded_count >= 5:
            score += 7
            findings.append(f"⚠️ Query string'de yoğun URL encoding ({encoded_count} karakter) (+7 puan)")

        return min(score, 30), findings  # Query'den max 30 puan

    def _analyze_host(self, host: str) -> Tuple[int, List[str]]:
        """
        Host kısmını analiz eder (subdomain yapısı, brand impersonation).
        Döndürür: (toplam puan, bulgular listesi)
        """
        score = 0
        findings = []
        host_lower = host.lower()

        # IP adresi kullanılıyor mu?
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            score += 20
            findings.append("🚨 Domain yerine IP adresi kullanılıyor — şüpheli hosting (+20 puan)")
            return score, findings

        parts = host_lower.split(".")

        # Çok fazla subdomain seviyesi (3+)
        subdomain_depth = len(parts) - 2  # TLD ve ana domain hariç
        if subdomain_depth >= 3:
            score += 10
            findings.append(f"⚠️ {subdomain_depth} katmanlı subdomain — karmaşık yapı (+10 puan)")
        elif subdomain_depth == 2:
            score += 5
            findings.append(f"ℹ️ 2 katmanlı subdomain (+5 puan)")

        # Brand impersonation tespiti
        # Örnek: paypal.security-update.tk → "paypal" subdomain'de, ama TLD .tk
        host_without_tld = ".".join(parts[:-1]) if len(parts) > 1 else host_lower
        for brand in BRAND_DOMAINS:
            if brand in host_without_tld:
                # Gerçek brand domain mi? (paypal.com, google.com vb.)
                is_real = host_lower in (f"{brand}.com", f"www.{brand}.com",
                                          f"{brand}.net", f"{brand}.org")
                if not is_real:
                    score += 25
                    findings.append(
                        f"🚨 Marka taklidi: `{brand}` kelimesi subdomain/domain'de var "
                        f"ama gerçek {brand}.com değil (+25 puan)"
                    )
                    break

        # Domain'de tire (-) fazlalığı (google-security-update.com gibi)
        main_domain = parts[-2] if len(parts) >= 2 else host_lower
        dash_count = main_domain.count("-")
        if dash_count >= 2:
            score += 8
            findings.append(f"⚠️ Domain'de {dash_count} adet tire — phishing pattern (+8 puan)")
        elif dash_count == 1:
            score += 3
            findings.append(f"ℹ️ Domain'de tire kullanımı (+3 puan)")

        return min(score, 40), findings  # Host'tan max 40 puan

    def analyze(self, raw_url: str) -> Dict:
        """
        Ana analiz fonksiyonu. Ham URL alır, tam rapor döner.
        
        Döndürür:
        {
            "original_url":     str,    # Girilen ham URL
            "normalized_url":   str,    # Normalize edilmiş URL
            "extracted_domain": str,    # ML modeline verilecek domain
            "components": {             # Ayrıştırılmış bileşenler
                "scheme":    str,
                "host":      str,
                "path":      str,
                "query":     str,
                "fragment":  str,
                "params":    dict,      # Query param sözlüğü
            },
            "url_risk_boost":   int,    # 0-50 arası ek risk puanı
            "risk_level":       str,    # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
            "findings":         list,   # Tespit edilen bulgular listesi
            "summary":          str,    # Kısa özet
        }
        """
        # 1. Normalize et
        normalized = self.normalize_url(raw_url)
        extracted_domain = self.extract_domain_from_url(raw_url)

        # 2. Parçala
        try:
            parsed = urlparse(normalized)
            components = {
                "scheme":   parsed.scheme,
                "host":     parsed.netloc.lower(),
                "path":     parsed.path,
                "query":    parsed.query,
                "fragment": parsed.fragment,
                "params":   {k: v[0] for k, v in parse_qs(parsed.query).items()}
            }
        except Exception as e:
            return {
                "original_url": raw_url,
                "normalized_url": normalized,
                "extracted_domain": extracted_domain,
                "components": {},
                "url_risk_boost": 0,
                "risk_level": "UNKNOWN",
                "findings": [f"URL ayrıştırılamadı: {e}"],
                "summary": "URL analizi başarısız."
            }

        # 3. Bileşenleri analiz et
        host_score, host_findings     = self._analyze_host(components["host"])
        path_score, path_findings     = self._analyze_path(components["path"])
        query_score, query_findings   = self._analyze_query(components["query"])

        all_findings = host_findings + path_findings + query_findings

        # HTTP (şifresiz) bağlantı — küçük ek puan
        if components["scheme"] == "http":
            http_bonus = 5
            all_findings.append("ℹ️ HTTP kullanılıyor (şifresiz bağlantı) (+5 puan)")
        else:
            http_bonus = 0

        # 4. Toplam URL boost (max 50)
        total_boost = min(50, host_score + path_score + query_score + http_bonus)

        # 5. Risk seviyesi
        if total_boost >= 35:
            risk_level = "CRITICAL"
        elif total_boost >= 20:
            risk_level = "HIGH"
        elif total_boost >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 6. Özet oluştur
        if not all_findings:
            summary = "URL yapısında belirgin phishing göstergesi tespit edilmedi."
        else:
            summary = (
                f"URL analizinde {len(all_findings)} şüpheli gösterge tespit edildi. "
                f"URL yapısı {risk_level} risk seviyesi taşıyor (+{total_boost} puan eklendi)."
            )

        return {
            "original_url":     raw_url,
            "normalized_url":   normalized,
            "extracted_domain": extracted_domain,
            "components":       components,
            "url_risk_boost":   total_boost,
            "risk_level":       risk_level,
            "findings":         all_findings,
            "summary":          summary,
        }

    def is_url(self, text: str) -> bool:
        """
        Verilen metnin domain mi yoksa tam URL mi olduğunu belirler.
        Slack bot'ta kullanılır.
        """
        text = text.strip()
        normalized = self.normalize_url(text)
        try:
            parsed = urlparse(normalized)
            # Path veya query varsa URL sayılır
            return bool(parsed.path and parsed.path != "/") or bool(parsed.query)
        except:
            return False


# =============================================================================
# SİNGLETON
# =============================================================================
url_parser = URLParser()
