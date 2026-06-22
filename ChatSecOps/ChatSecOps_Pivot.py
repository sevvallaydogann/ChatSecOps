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
  - Her domain en fazla PIVOT_MAX_DEPTH kez pivot zincirinde çalışır
  - Aynı oturumda zaten analiz edilmişler atlanır
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
# Ana analizin yavaşlamaması için
PIVOT_DELAY = 2


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
            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 404:
                logger.info(f"[PIVOT] Shodan'da {ip_address} bulunamadı")
                return []

            if response.status_code != 200:
                logger.warning(f"[PIVOT] Shodan HTTP {response.status_code}")
                return []

            data = response.json()
            hostnames = data.get("hostnames", [])

            results = []
            for hostname in hostnames:
                # Kendini, boşları ve wildcard'ları atla
                if not hostname or hostname == exclude_domain or hostname.startswith("*"):
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
            logger.warning("[PIVOT] Shodan timeout")
            return []
        except Exception as e:
            logger.error(f"[PIVOT] Shodan hatası: {e}")
            return []

    # =========================================================================
    # ANA FONKSİYON: PIVOT ANALİZİNİ ÇALIŞTIR
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

        Parametreler:
            trigger_domain:     Zinciri başlatan domain
            ip_address:         Tespit edilen IP
            trigger_risk_score: Başlatan domain'in risk skoru
            already_analyzed:   Bu oturumda zaten analiz edilmiş domainler seti (döngü koruması)

        Döndürür:
            {
                "pivot_triggered": bool,
                "ip_address": str,
                "total_related": int,
                "db_domains": [...],
                "shodan_domains": [...],
                "auto_analyzed": [...],
                "slack_message": str
            }
        """

        if already_analyzed is None:
            already_analyzed = {trigger_domain}

        logger.info(f"[PIVOT] Zincir başlatıldı: {trigger_domain} → IP: {ip_address}")

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
            logger.info(f"[PIVOT] {trigger_domain} için pivot bulunamadı")
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

        # Maksimum PIVOT_MAX_DEPTH kadar yeni domain analiz et
        domains_to_analyze = new_domains[:PIVOT_MAX_DEPTH]

        for domain_info in domains_to_analyze:
            domain = domain_info["domain"]
            already_analyzed.add(domain)

            logger.info(f"[PIVOT] Otomatik analiz başlatılıyor: {domain}")
            time.sleep(PIVOT_DELAY)  # API rate limit koruması

            try:
                response = requests.get(
                    f"{self.backend_api}/enrich-and-summarize/domain/{domain}",
                    timeout=90
                )

                if response.status_code == 200:
                    result = response.json()
                    model_data = result.get("ham_veriler", {}).get("kendi_modelimiz", {})
                    risk = float(model_data.get("risk_skoru_yuzde", "0").replace("%", ""))
                    pred = model_data.get("tahmin_sinifi", 0)

                    auto_analyzed.append({
                        "domain": domain,
                        "risk_score": risk,
                        "prediction": pred,
                        "verdict": "MALICIOUS" if pred == 1 else "SAFE"
                    })

                    # all_related'i güncelle
                    if domain in all_related:
                        all_related[domain]["risk_score"] = risk
                        all_related[domain]["prediction"] = pred

                    logger.info(f"[PIVOT] ✅ {domain} analiz tamamlandı (Risk: {risk}%)")

                else:
                    logger.warning(f"[PIVOT] {domain} analiz başarısız: HTTP {response.status_code}")

            except requests.exceptions.Timeout:
                logger.warning(f"[PIVOT] {domain} analiz timeout")
            except Exception as e:
                logger.error(f"[PIVOT] {domain} analiz hatası: {e}")

        # 4. Slack mesajını oluştur
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
        Pivot zinciri bulgularını Slack'e gönderilecek formata çevirir.
        """
        malicious_count = sum(
            1 for d in related_domains
            if d.get("prediction") == 1 or (d.get("risk_score") and d["risk_score"] >= 70)
        )

        # Başlık satırı
        lines = [
            f"🕸️ *IOC Pivot Zinciri Tespit Edildi*",
            f"",
            f"*Tetikleyen Domain:* `{trigger_domain}` (Risk: {trigger_risk_score:.0f}%)",
            f"*Paylaşılan IP:* `{ip_address}`",
            f"*Toplam İlişkili Domain:* {len(related_domains)}",
        ]

        if malicious_count > 0:
            lines.append(f"*⚠️ Zararlı Tespit:* {malicious_count} domain bu IP'de zararlı olarak işaretli!")
        
        lines.append("")

        # DB'den bulunanlar
        db_found = [d for d in related_domains if d["source"] in ("our_db", "both")]
        if db_found:
            lines.append("*📁 Veritabanımızda Bu IP'de Görülen Domainler:*")
            for d in db_found[:5]:  # Max 5 göster
                risk = d.get("risk_score", 0) or 0
                icon = "🔴" if risk >= 70 else "🟡" if risk >= 30 else "🟢"
                lines.append(f"  {icon} `{d['domain']}` — Risk: {risk:.0f}% | Son görülme: {d.get('last_seen', 'N/A')}")
            if len(db_found) > 5:
                lines.append(f"  _...ve {len(db_found) - 5} domain daha_")
            lines.append("")

        # Otomatik analiz edilenler
        if auto_analyzed:
            lines.append("*🤖 Otomatik Analiz Edildi (Shodan'dan Yeni):*")
            for d in auto_analyzed:
                icon = "🔴" if d["prediction"] == 1 else "🟢"
                lines.append(f"  {icon} `{d['domain']}` — {d['verdict']} ({d['risk_score']:.0f}%)")
            lines.append("")

        # Kampanya uyarısı
        if malicious_count >= 3:
            lines.append("🚨 *KAMPANYA UYARISI:* Bu IP üzerinde birden fazla zararlı domain tespit edildi.")
            lines.append("Ortak altyapı kullanımı — koordineli bir saldırı kampanyası olabilir.")

        return "\n".join(lines)


# =============================================================================
# SİNGLETON
# =============================================================================
pivot_engine = PivotEngine()
