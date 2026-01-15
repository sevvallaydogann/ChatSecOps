"""
ChatSecOps_Intelligence.py
Gerçek zamanlı Threat Intelligence Feed entegrasyonu

Özellikler:
- Public threat feeds'ten domain/IP kontrolü
- IOC (Indicator of Compromise) tracking
- OSINT data enrichment
- Screenshot/Visual evidence
"""

import requests
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import hashlib
import json

class IntelligenceEngine:
    """
    Threat Intelligence toplama ve zenginleştirme motoru
    """
    
    def __init__(self):
        self.feeds = {
            "urlhaus": "https://urlhaus-api.abuse.ch/v1/",
            "phishtank": "http://data.phishtank.com/data/online-valid.json",
            "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
        }
        
        self.cache = {}  # Basit cache mekanizması
        self.cache_timeout = timedelta(hours=1)
    
    def check_urlhaus(self, domain: str) -> Optional[Dict]:
        """
        URLhaus feed'inden domain kontrolü
        abuse.ch'nin gerçek zamanlı malware URL database'i
        """
        try:
            response = requests.post(
                f"{self.feeds['urlhaus']}host/",
                data={"host": domain},
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    urls = data.get("urls", [])
                    
                    if urls:
                        latest = urls[0]
                        return {
                            "found": True,
                            "threat_type": latest.get("threat"),
                            "malware_families": list(set([u.get("threat") for u in urls if u.get("threat")])),
                            "url_count": len(urls),
                            "last_seen": latest.get("date_added"),
                            "tags": latest.get("tags", []),
                            "source": "URLhaus"
                        }
                
                return {"found": False, "source": "URLhaus"}
        
        except Exception as e:
            print(f"⚠️ URLhaus sorgusu başarısız: {e}")
            return {"error": str(e), "source": "URLhaus"}
    
    def check_threatfox(self, domain: str) -> Optional[Dict]:
        """
        ThreatFox IOC kontrolü
        """
        try:
            response = requests.post(
                self.feeds["threatfox"],
                json={
                    "query": "search_ioc",
                    "search_term": domain
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get("query_status") == "ok":
                    iocs = data.get("data", [])
                    
                    if iocs:
                        latest = iocs[0]
                        return {
                            "found": True,
                            "ioc_type": latest.get("ioc_type"),
                            "threat_type": latest.get("threat_type"),
                            "malware": latest.get("malware"),
                            "confidence": latest.get("confidence_level"),
                            "tags": latest.get("tags", []),
                            "first_seen": latest.get("first_seen"),
                            "source": "ThreatFox"
                        }
                
                return {"found": False, "source": "ThreatFox"}
        
        except Exception as e:
            print(f"⚠️ ThreatFox sorgusu başarısız: {e}")
            return {"error": str(e), "source": "ThreatFox"}
    
    def get_osint_data(self, domain: str) -> Dict:
        """
        Public OSINT kaynaklarından veri toplama
        """
        osint_data = {
            "urlhaus": self.check_urlhaus(domain),
            "threatfox": self.check_threatfox(domain),
        }
        
        # En az bir kaynakta tehdit bulundu mu?
        threats_found = any(
            data.get("found", False) 
            for data in osint_data.values() 
            if isinstance(data, dict)
        )
        
        return {
            "threats_detected": threats_found,
            "sources": osint_data,
            "checked_at": datetime.now().isoformat()
        }
    
    def get_visual_evidence(self, domain: str) -> str:
        """
        Domain'in screenshot'ını thum.io üzerinden al (Canlı ve Hızlı)
        """
        # thum.io servisi anlık olarak siteye gidip fotoğrafını çeker.
        # URLScan gibi bekleme süresi veya UUID gerektirmez.
        return f"https://image.thum.io/get/width/600/crop/800/noanimate/http://{domain}"
    
    def get_hunting_logic(self) -> str:
        """
        Threat hunting için ek mantık kuralları
        Gemini'ye gönderilecek extra context
        """
        rules = """
--- [THREAT HUNTING LOGIC] ---

Aşağıdaki durumlarda EXTRA DİKKATLİ ol:

1. **Zero-Day Indicators:**
   - Domain çok yeni (< 30 gün)
   - VirusTotal'da tespit yok AMA ML modelimiz yüksek risk diyor
   - → Bu "Zero-Day" olabilir, Manual Review öner

2. **Campaign Indicators:**
   - Benzer isimli birden fazla domain (typosquatting pattern)
   - Aynı IP'de çok sayıda domain
   - → Muhtemelen organized threat campaign

3. **Infrastructure Patterns:**
   - Bulletproof hosting (RU, CN gibi ASN'ler)
   - Suspicious TLD (.tk, .ml, .ga, .cf - free TLD'ler)
   - → Infrastructure-based threat

4. **Behavioral Anomalies:**
   - SPF/DKIM/DMARC yok (phishing indicator)
   - SSL sertifika problemi
   - → Phishing/social engineering riski

5. **External Intel Correlation:**
   - URLhaus/ThreatFox'ta görülmüş
   - → Confirmed threat, immediate action

Bu faktörleri analizine dahil et ve önceliğini buna göre ayarla.
"""
        return rules


# Singleton instance
intel_engine = IntelligenceEngine()


# ============================================================================
# MAIN.PY İÇİN ENTEGRASYON FONKSİYONU
# ============================================================================

def enrich_with_osint(domain: str, base_analysis: Dict) -> Dict:
    """
    Base analizi OSINT verileriyle zenginleştir
    """
    print(f"      [>] OSINT verileri toplanıyor: {domain}")
    
    osint_data = intel_engine.get_osint_data(domain)
    
    # Base analysis'e OSINT'i ekle
    enriched = base_analysis.copy()
    enriched["osint_intelligence"] = osint_data
    
    # Eğer threat feed'lerde bulunduysa, risk seviyesini artır
    if osint_data.get("threats_detected"):
        print(f"      ⚠️ [ALERT] {domain} threat feed'lerde tespit edildi!")
        enriched["threat_feed_alert"] = True
    
    return enriched


# ============================================================================
# SLACK BOT İÇİN HELPER
# ============================================================================

def format_osint_results(osint_data: Dict) -> str:
    """
    OSINT sonuçlarını Slack formatında döndür
    """
    if not osint_data.get("threats_detected"):
        return "✅ Public threat feed'lerde bu domain bulunamadı."
    
    text = "\n🚨 *Public Threat Intelligence Alerts*\n\n"
    
    sources = osint_data.get("sources", {})
    
    # URLhaus
    urlhaus = sources.get("urlhaus", {})
    if urlhaus.get("found"):
        text += f"• *URLhaus:* {urlhaus.get('url_count')} malicious URL tespit edildi\n"
        text += f"  Malware: {', '.join(urlhaus.get('malware_families', []))}\n"
    
    # ThreatFox
    threatfox = sources.get("threatfox", {})
    if threatfox.get("found"):
        text += f"• *ThreatFox:* IOC tespit edildi\n"
        text += f"  Malware: {threatfox.get('malware', 'N/A')}\n"
        text += f"  Confidence: {threatfox.get('confidence', 'N/A')}\n"
    
    return text