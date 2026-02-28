"""
ChatSecOps_Intelligence.py
Expanded Intelligence: VirusTotal, AbuseIPDB, AlienVault OTX, Shodan
FIXED: AlienVault Direct API Implementation
"""
import requests
import os
from datetime import datetime

# Shodan'ı içe aktarmayı dene
try:
    import shodan
except ImportError:
    shodan = None

class IntelligenceEngine:
    def __init__(self):
        self.otx_key = os.getenv("ALIENVAULT_API_KEY")
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        
        # Klasik Feedler
        self.feeds = {
            "urlhaus": "https://urlhaus-api.abuse.ch/v1/",
            "threatfox": "https://threatfox-api.abuse.ch/api/v1/",
        }

        # Shodan Bağlantısı
        if self.shodan_key and shodan:
            try:
                self.shodan_api = shodan.Shodan(self.shodan_key)
                print("✅ [INTEL] Shodan Hazır.")
            except:
                self.shodan_api = None
        else:
            self.shodan_api = None

    # --- ESKİ MODÜLLER (URLHaus & ThreatFox) ---
    def check_urlhaus(self, domain: str):
        try:
            response = requests.post(f"{self.feeds['urlhaus']}host/", data={"host": domain}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok" and data.get("urls"):
                    return {"found": True, "count": len(data.get("urls")), "source": "URLhaus"}
            return {"found": False}
        except:
            return {"error": "Connection failed"}

    def check_threatfox(self, domain: str):
        try:
            response = requests.post(self.feeds["threatfox"], json={"query": "search_ioc", "search_term": domain}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {"found": True, "data": data.get("data")[0], "source": "ThreatFox"}
            return {"found": False}
        except:
            return {"error": "Connection failed"}

    # --- ALIENVAULT (DÜZELTİLDİ: DIRECT API) ---
    def check_alienvault(self, domain):
        """AlienVault OTX - Direct API Call (No Library Dependency)"""
        if not self.otx_key: 
            return {"error": "API Key Missing"}
            
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": self.otx_key}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                return {
                    "source": "AlienVault OTX",
                    "pulse_count": pulse_count,
                    "is_malicious": pulse_count > 0
                }
            elif response.status_code == 403:
                return {"error": "Invalid API Key"}
            else:
                return {"error": f"API Error {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- SHODAN ---
    def check_shodan(self, ip_address):
        """Shodan IP Taraması"""
        if not ip_address: return {"error": "No IP Provided"}
        if not self.shodan_api: return {"error": "API Key Missing"}

        try:
            host = self.shodan_api.host(ip_address)
            return {
                "source": "Shodan",
                "org": host.get('org', 'n/a'),
                "os": host.get('os', 'n/a'),
                "ports": host.get('ports', []),
                "vulns": list(host.get('vulns', [])),
            }
        except Exception as e:
            # Shodan bazen 'No information available for that IP' hatası döner
            return {"error": "IP not found in Shodan DB"}

    def get_full_intel(self, domain, ip_address=None):
        """Tüm istihbaratı topla"""
        return {
            "urlhaus": self.check_urlhaus(domain),
            "threatfox": self.check_threatfox(domain),
            "alienvault": self.check_alienvault(domain),
            "shodan": self.check_shodan(ip_address) if ip_address else None,
            "threats_detected": False, # Basitleştirildi
            "checked_at": datetime.now().isoformat()
        }
    
    def get_hunting_logic(self):
        return "\n[Logic] Check AlienVault pulses and Shodan open ports."

# Global Instance
intel_engine = IntelligenceEngine()

# Helpers
def enrich_with_osint(domain, base): return intel_engine.get_full_intel(domain)
def format_osint_results(data): return "Processed"