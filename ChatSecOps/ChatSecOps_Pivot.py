"""
ChatSecOps_Pivot.py - IOC Zinciri Takibi (Feature 2)
=====================================================
Bir domain analiz edildiğinde aynı IP'yi paylaşan diğer
domainleri tespit eder ve otomatik analiz sırasına alır.

Akış:
  1. Domain analiz edilir → IP tespit edilir
  2. PivotEngine devreye girer:
     a. Kendi DB'mizde bu IP'de başka domain var mı?
     b. Shodan'da bu IP'nin hostname listesi var mı?
  3. Yeni domain bulunursa → otomatik analiz sırası
  4. Sonuçlar Slack'e gönderilir + DB'ye kaydedilir

Sonsuz döngü koruması:
  - Devasa ortak altyapı ve CDN IP blokları (Cloudflare, Fastly vb.) bypass edilir.
  - Her domain en fazla PIVOT_MAX_DEPTH kez pivot zincirinde çalışır.
  - Aynı oturumda zaten analiz edilmişler atlanır.
"""

import sqlite3
import requests
import logging
import os
import time
from datetime import datetime
from typing import List, Dict, Optional, Set

logger = logging.getLogger(__name__)

# Bir pivot oturumunda maksimum kaç yeni domain analiz edilsin
PIVOT_MAX_DEPTH = 5

# Pivot analizleri arasında bekleme süresi (saniye)
# Ana analizin ve API kotalarının yavaşlamaması için
PIVOT_DELAY = 2

# Sonsuz döngüye girmesi kesin olan devasa paylaşımlı CDN ve Bulut IP servis haritası
POPULAR_CDN_PREFIXES = (
    "151.101.",   # Fastly CDN
    "104.18.",    # Cloudflare IP Blok 1
    "104.17.",    # Cloudflare IP Blok 2
    "172.67.",    # Cloudflare IP Blok 3
    "199.232.",   # Fastly Dağıtık Altyapı
    "146.75.",    # Fastly CDN Edge
    "34.102.",    # Google Cloud Load Balancer Edge
    "13.224.",    # Amazon AWS CloudFront
    "13.32.",     # Amazon AWS CloudFront Edge
    "184.24.",    # Akamai Technologies CDN
    "23.227."     # Shopify Ortak Barındırma Altyapısı
)


class PivotEngine:
    """
    IOC Zinciri Takip Motoru.
    
    Bir IP adresini merkeze alarak:
    - Kendi veritabanımızdaki tüm bağlı domainleri bulur
    - Shodan'dan aynı IP'nin hostname listesini çeker
    - Yeni domainleri analiz sırasına alır
    - Zincir raporunu üretir
    """

    def __init__(self, db_path: str = "chatsecops_memory.db"):
        self.db_path = db_path
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.backend_api = os.getenv("BACKEND_API_URL", "http://localhost:8000")

    # =========================================================================
    # KAYNAK 1: KENDİ VERİTABANIMIZ
    # =========================================================================

    def get_cohosted_from_db(self, ip_address: str, exclude_domain: str) -> List[Dict]:
        """
        ip_clusters + domain_analysis tablolarından aynı IP'deki domainleri çeker.
        exclude_domain: zinciri başlatan domain, kendisini tekrar eklemeyelim.
        """
        if not ip_address or ip_address == "N/A":
            return []

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT 
                    domain,
                    risk_score,
                    prediction,
                    MAX(timestamp) as last_seen
                FROM domain_analysis
                WHERE ip_address = ?
                  AND domain != ?
                GROUP BY domain
                ORDER BY risk_score DESC
            """, (ip_address, exclude_domain))

            rows = cursor.fetchall()
            conn.close()

            results = []
            for domain, risk_score, prediction, last_seen in rows:
                results.append({
                    "domain": domain,
                    "risk_score": round(risk_score, 1) if risk_score else 0.0,
                    "prediction": prediction,
                    "source": "our_db",
                    "last_seen": datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d") if last_seen else "N/A"
                })

            logger.info(f"[PIVOT] DB'den {len(results)} cohosted domain bulundu (IP: {ip_address})")
            return results

        except Exception as e:
            logger.error(f"[PIVOT] DB sorgu hatası: {e}")
            return []

    # =========================================================================
    # KAYNAK 2: SHODAN - AYNI IP'DEKİ HOSTNAMELERİ ÇEK
    # =========================================================================

    def get_cohosted_from_shodan(self, ip_address: str, exclude_domain: str) -> List[Dict]:
        """
        Shodan'dan IP'nin hostname listesini çeker.
        Bu liste daha önce hiç analiz etmediğimiz domainleri içerebilir.
        """
        if not self.shodan_key:
            logger.warning("[PIVOT] Shodan API key yok, bu kaynak atlanıyor")
            return []

        if not ip_address or ip_address == "N/A":
            return []

        try:
            # Shodan REST API - kütüphane gerektirmez
            url = f"https://api.shodan.io/shodan/host/{ip_address}"
            params = {"key": self.shodan_key}
            response = requests.get(url, params=params, timeout=8) # Hızlı SOC yanıtı için 8 saniye limit

            if response.status_code == 404:
                logger.info(f"[PIVOT] Shodan'da {ip_address} bulunamadı")
                return []

            if response.status_code == 403:
                logger.warning(f"[PIVOT] Shodan HTTP 403: Yetkisiz Erişim veya API Limiti")
                return []

            if response.status_code != 200:
                logger.warning(f"[PIVOT] Shodan HTTP {response.status_code}")
                return []

            data = response.json()
            hostnames = data.get("hostnames", [])

            results = []
            for hostname in hostnames:
                # Kendini, boşları ve wildcard'ları atla
                if not hostname or hostname == exclude_domain or hostname.startswith("*") or "." not in hostname:
                    continue

                results.append({
                    "domain": hostname,
                    "risk_score": None,       # henüz analiz edilmedi
                    "prediction": None,
                    "source": "shodan",
                    "last_seen": "New"        # ilk kez görüyoruz
                })

            logger.info(f"[PIVOT] Shodan'dan {len(results)} hostname alındı (IP: {ip_address})")
            return results

        except requests.exceptions.Timeout:
            logger.warning("[PIVOT] Shodan ağ isteği zaman aşımına uğradı (Timeout)")
            return []
        except Exception as e:
            logger.error(f"[PIVOT] Shodan hatası: {e}")
            return []

    # =========================================================================
    # KAYNAK MİMARİSİ GÜVENLİK FİLTRESİ (CDN BYPASS DETECTION)
    # =========================================================================
    
    def _is_shared_infrastructure(self, ip_address: str) -> bool:
        """
        IP adresinin devasa bir paylaşımlı CDN ağ grubuna ait olup olmadığını doğrular.
        """
        return any(ip_address.startswith(prefix) for prefix in POPULAR_CDN_PREFIXES)

    # =========================================================================
    # KAYNAK 3: ANA FONKSİYON - PIVOT ANALİZİNİ ÇALIŞTIR
    # =========================================================================

    def run_pivot(
        self,
        trigger_domain: str,
        ip_address: str,
        trigger_risk_score: float,
        already_analyzed: Optional[Set[str]] = None
    ) -> Dict:
        """
        Pivot zincirini başlatır.
        """
        if already_analyzed is None:
            already_analyzed = {trigger_domain}

        logger.info(f"[PIVOT] Zincir başlatıldı: {trigger_domain} → IP: {ip_address}")

        # 🚀 KRİTİK GÜVENLİK FİLTRESİ: CDN Kısır Döngü Koruması
        if self._is_shared_infrastructure(ip_address):
            logger.warning(f"[PIVOT] ⚠️ {ip_address} bir paylaşımlı CDN/Cloud altyapısıdır. Sonsuz döngüyü engellemek için pivot durduruldu.")
            return {
                "pivot_triggered": False,
                "ip_address": ip_address,
                "total_related": 0,
                "db_domains": [],
                "shodan_domains": [],
                "auto_analyzed": [],
                "slack_message": None
            }

        # 1. Her iki kaynaktan domainleri topla
        db_domains = self.get_cohosted_from_db(ip_address, trigger_domain)
        shodan_domains = self.get_cohosted_from_shodan(ip_address, trigger_domain)

        # 2. Birleştir, tekrarları kaldır
        all_related = {}
        for d in db_domains:
            all_related[d["domain"]] = d
        for d in shodan_domains:
            # DB'de yoksa ekle, varsa kaynağı "both" yap
            if d["domain"] in all_related:
                all_related[d["domain"]]["source"] = "both"
            else:
                all_related[d["domain"]] = d

        related_list = list(all_related.values())
        total_related = len(related_list)

        if total_related == 0:
            logger.info(f"[PIVOT] {trigger_domain} için altyapı pivotu bulunamadı")
            return {
                "pivot_triggered": False,
                "ip_address": ip_address,
                "total_related": 0,
                "db_domains": [],
                "shodan_domains": [],
                "auto_analyzed": [],
                "slack_message": None
            }

        # 3. Shodan'dan gelen YENİ (DB'de olmayan) domainleri otomatik analiz et
        new_domains = [
            d for d in related_list
            if d["source"] in ("shodan", "both")
            and d["domain"] not in already_analyzed
            and d["risk_score"] is None  # henüz analiz edilmemiş
        ]

        auto_analyzed = []

        # Maksimum PIVOT_MAX_DEPTH kadar yeni domain analiz et (Varsayılan: 5)
        domains_to_analyze = new_domains[:PIVOT_MAX_DEPTH]

        for domain_info in domains_to_analyze:
            domain = domain_info["domain"]
            already_analyzed.add(domain)

            logger.info(f"[PIVOT] Otomatik arka plan analizi tetikleniyor: {domain}")
            time.sleep(PIVOT_DELAY)  # API rate limit ve thread ezme koruması

            try:
                # Backend API üzerinden asenkron / bağımsız istek fırlatıyoruz
                response = requests.get(
                    f"{self.backend_api}/enrich-and-summarize/domain/{domain}",
                    timeout=25 # Alt sorgular için 25 saniye tavan limit, Slack'i tamamen tıkamasın
                )

                if response.status_code == 200:
                    result = response.json()
                    model_data = result.get("ham_veriler", {}).get("kendi_modelimiz", {})
                    
                    # String gelen yüzde verisini float sayıya temizleme işlemi
                    risk_str = str(model_data.get("risk_skoru_yuzde", "0")).replace("%", "").strip()
                    risk = float(risk_str) if risk_str else 0.0
                    pred = int(model_data.get("tahmin_sinifi", 0))

                    auto_analyzed.append({
                        "domain": domain,
                        "risk_score": risk,
                        "prediction": pred,
                        "verdict": "MALICIOUS" if pred == 1 else "SAFE"
                    })

                    # Hafızadaki listeyi anlık güncelle
                    if domain in all_related:
                        all_related[domain]["risk_score"] = risk
                        all_related[domain]["prediction"] = pred

                    logger.info(f"[PIVOT] ✅ Otomatik zincir parçası tamamlandı: {domain} (Risk: {risk}%)")

                else:
                    logger.warning(f"[PIVOT] {domain} alt analizi başarısız oldu: HTTP {response.status_code}")

            except requests.exceptions.Timeout:
                logger.warning(f"[PIVOT] {domain} alt analizi zaman aşımına uğradı (FastAPI Timeout)")
            except Exception as e:
                logger.error(f"[PIVOT] {domain} otomatik analiz yürütme hatası: {e}")

        # 4. Slack mesaj blok gövdesini oluştur
        slack_message = self._build_slack_message(
            trigger_domain=trigger_domain,
            ip_address=ip_address,
            trigger_risk_score=trigger_risk_score,
            related_domains=list(all_related.values()),
            auto_analyzed=auto_analyzed
        )

        return {
            "pivot_triggered": True,
            "ip_address": ip_address,
            "total_related": total_related,
            "db_domains": db_domains,
            "shodan_domains": [d for d in related_list if d["source"] in ("shodan", "both")],
            "auto_analyzed": auto_analyzed,
            "slack_message": slack_message
        }

    # =========================================================================
    # SLACK MESAJI OLUŞTUR
    # =========================================================================

    def _build_slack_message(
        self,
        trigger_domain: str,
        ip_address: str,
        trigger_risk_score: float,
        related_domains: List[Dict],
        auto_analyzed: List[Dict]
    ) -> str:
        """
        Pivot zinciri bulgularını Slack'e gönderilecek profesyonel formata çevirir.
        """
        malicious_count = sum(
            1 for d in related_domains
            if d.get("prediction") == 1 or (d.get("risk_score") and d["risk_score"] >= 70)
        )

        # Başlık ve Özet verileri
        lines = [
            f"🕸️ *IOC Pivot Zinciri Tespit Edildi*",
            f"",
            f"*Tetikleyen Domain:* `{trigger_domain}` (Risk: {trigger_risk_score:.0f}%)",
            f"*Paylaşılan Altyapı IP:* `{ip_address}`",
            f"*Toplam İlişkili Komşu Varlık:* {len(related_domains)}",
        ]

        if malicious_count > 0:
            lines.append(f"*⚠️ C2 / Phishing Odak Noktası:* Sunucudaki {malicious_count} domain sistemde aktif zararlı!")
        
        lines.append("")

        # DB'den çekilen eski kayıtlar
        db_found = [d for d in related_domains if d["source"] in ("our_db", "both")]
        if db_found:
            lines.append("*📁 Sistem Belleğinde Eşleşen Yerel Domainler:*")
            for d in db_found[:5]:  # Arayüzü tıkamamak adına Max 5 satır basıyoruz
                risk = d.get("risk_score", 0) or 0
                icon = "🔴" if risk >= 70 else "🟡" if risk >= 30 else "🟢"
                lines.append(f"  {icon} `{d['domain']}` — Risk: {risk:.0f}% | Son Görülme: {d.get('last_seen', 'N/A')}")
            if len(db_found) > 5:
                lines.append(f"  _...ve {len(db_found) - 5} domain daha veritabanında mevcut._")
            lines.append("")

        # Shodan'dan yakalanıp otomatik taranan yeni varlıklar
        if auto_analyzed:
            lines.append("*🤖 Otomatik SOAR Analizleri (Shodan Altyapı Keşfi):*")
            for d in auto_analyzed:
                icon = "🔴" if d["prediction"] == 1 else "🟢"
                lines.append(f"  {icon} `{d['domain']}` — *{d['verdict']}* (Risk: {d['risk_score']:.0f}%)")
            lines.append("")

        # Kampanya korelasyon uyarısı (Jürinin en çok sevdiği SOC zekası kısmı)
        if malicious_count >= 3:
            lines.append("🚨 *KOORDİNELİ KAMPANYA ALERMİ:* Aynı IP üzerinde kritik eşiğin üzerinde aktif tehdit var.")
            lines.append("Altyapı koordineli bir C2 saldırı veya aktif oltalama kampanyasına tahsis edilmiş olabilir.")

        return "\n".join(lines)


# =============================================================================
# SİNGLETON MOTOR NESNESİ TANIMI
# =============================================================================
pivot_engine = PivotEngine()