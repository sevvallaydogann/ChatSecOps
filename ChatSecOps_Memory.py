"""
ChatSecOps_Memory.py
Tehdit İstihbarat Hafıza Sistemi

Özellikler:
- Her analizi veritabanına kaydet
- Benzer domain'leri tespit et
- Temporal pattern analizi (aynı IP'den gelen domain'ler)
- Threat actor profiling (campaign detection)
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
import json
from difflib import SequenceMatcher
import re

class ThreatMemoryEngine:
    """
    Akıllı tehdit hafıza sistemi
    """
    
    def __init__(self, db_path: str = "chatsecops_memory.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Veritabanını oluştur"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Ana analiz tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score REAL,
                prediction INTEGER,
                ip_address TEXT,
                country TEXT,
                asn INTEGER,
                tld TEXT,
                vt_malicious INTEGER,
                abuse_score REAL,
                xai_summary TEXT,
                full_analysis JSON,
                analyst_feedback TEXT DEFAULT NULL,
                false_positive BOOLEAN DEFAULT 0
            )
        """)
        
        # Domain similarity index
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_similarity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain1 TEXT,
                domain2 TEXT,
                similarity_score REAL,
                detected_at TEXT
            )
        """)
        
        # IP clustering
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                domain_count INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                threat_level TEXT
            )
        """)
        
        # Campaign tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT,
                indicators TEXT,
                domain_count INTEGER,
                created_at TEXT,
                last_activity TEXT
            )
        """)
        
        conn.commit()
        conn.close()
        print("✅ [Memory] Veritabanı hazır")
    
    def store_analysis(self, domain: str, analysis_data: dict):
        """Analiz sonucunu kaydet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Veriyi parse et
        model_data = analysis_data.get("ham_veriler", {}).get("kendi_modelimiz", {})
        vt_data = analysis_data.get("ham_veriler", {}).get("virustotal", {})
        abuse_data = analysis_data.get("ham_veriler", {}).get("abuseipdb", {})
        
        risk_score = float(model_data.get("risk_skoru_yuzde", "0").replace("%", ""))
        prediction = model_data.get("tahmin_sinifi", 0)
        ip_address = model_data.get("tespit_edilen_ip", "N/A")
        country = model_data.get("tespit_edilen_ulke", "N/A")
        
        # XAI özetini al
        xai_data = model_data.get("xai_aciklama", {})
        xai_summary = json.dumps(xai_data) if xai_data else None
        
        # TLD'yi çıkar
        tld = domain.split('.')[-1] if '.' in domain else 'unknown'
        
        cursor.execute("""
            INSERT INTO domain_analysis 
            (domain, timestamp, risk_score, prediction, ip_address, country, 
             tld, vt_malicious, abuse_score, xai_summary, full_analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            datetime.now().isoformat(),
            risk_score,
            prediction,
            ip_address,
            country,
            tld,
            vt_data.get("malicious", 0),
            abuse_data.get("abuseConfidenceScore", 0),
            xai_summary,
            json.dumps(analysis_data)
        ))
        
        conn.commit()
        
        # IP clustering güncelle
        self._update_ip_cluster(cursor, ip_address, domain, risk_score)
        
        # Benzer domain'leri kontrol et
        similar_domains = self._find_similar_domains(cursor, domain)
        
        conn.commit()
        conn.close()
        
        print(f"✅ [Memory] {domain} kaydedildi (Risk: {risk_score}%)")
        
        return {
            "stored": True,
            "similar_domains": similar_domains,
            "memory_insights": self.get_domain_insights(domain)
        }
    
    def _update_ip_cluster(self, cursor, ip_address: str, domain: str, risk_score: float):
        """IP clustering güncelle"""
        if ip_address == "N/A":
            return
        
        # IP daha önce görüldü mü?
        cursor.execute("SELECT * FROM ip_clusters WHERE ip_address = ?", (ip_address,))
        existing = cursor.fetchone()
        
        threat_level = "HIGH" if risk_score >= 80 else "MEDIUM" if risk_score >= 50 else "LOW"
        
        if existing:
            # Güncelle
            cursor.execute("""
                UPDATE ip_clusters 
                SET domain_count = domain_count + 1,
                    last_seen = ?,
                    threat_level = ?
                WHERE ip_address = ?
            """, (datetime.now().isoformat(), threat_level, ip_address))
        else:
            # Yeni kayıt
            cursor.execute("""
                INSERT INTO ip_clusters 
                (ip_address, domain_count, first_seen, last_seen, threat_level)
                VALUES (?, 1, ?, ?, ?)
            """, (ip_address, datetime.now().isoformat(), datetime.now().isoformat(), threat_level))
    
    def _find_similar_domains(self, cursor, domain: str, threshold: float = 0.7) -> List[Dict]:
        """Benzer domain'leri bul (typosquatting detection)"""
        cursor.execute("SELECT domain, risk_score FROM domain_analysis WHERE domain != ?", (domain,))
        all_domains = cursor.fetchall()
        
        similar = []
        for stored_domain, risk_score in all_domains:
            similarity = self._calculate_similarity(domain, stored_domain)
            if similarity >= threshold:
                similar.append({
                    "domain": stored_domain,
                    "similarity": round(similarity, 2),
                    "risk_score": risk_score
                })
                
                # Similarity kaydı ekle
                cursor.execute("""
                    INSERT INTO domain_similarity (domain1, domain2, similarity_score, detected_at)
                    VALUES (?, ?, ?, ?)
                """, (domain, stored_domain, similarity, datetime.now().isoformat()))
        
        return similar[:5]  # En çok 5 benzer domain döndür
    
    def _calculate_similarity(self, domain1: str, domain2: str) -> float:
        """İki domain arasındaki benzerliği hesapla"""
        # TLD'yi çıkar
        name1 = '.'.join(domain1.split('.')[:-1])
        name2 = '.'.join(domain2.split('.')[:-1])
        
        return SequenceMatcher(None, name1, name2).ratio()
    
    def get_domain_insights(self, domain: str) -> Dict:
        """Domain hakkında hafıza sisteminden içgörüler al"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Domain daha önce analiz edilmiş mi?
        cursor.execute("""
            SELECT COUNT(*), AVG(risk_score), MIN(timestamp), MAX(timestamp)
            FROM domain_analysis WHERE domain = ?
        """, (domain,))
        
        count, avg_risk, first_seen, last_seen = cursor.fetchone()
        
        insights = {
            "is_known": count > 0,
            "analysis_count": count,
            "avg_risk_score": round(avg_risk, 2) if avg_risk else None,
            "first_seen": first_seen,
            "last_seen": last_seen
        }
        
        # Aynı IP'den gelen domain'leri bul
        if count > 0:
            cursor.execute("""
                SELECT ip_address FROM domain_analysis 
                WHERE domain = ? ORDER BY timestamp DESC LIMIT 1
            """, (domain,))
            
            ip = cursor.fetchone()
            if ip and ip[0] != "N/A":
                cursor.execute("""
                    SELECT COUNT(DISTINCT domain) FROM domain_analysis 
                    WHERE ip_address = ? AND domain != ?
                """, (ip[0], domain))
                
                cohosted_count = cursor.fetchone()[0]
                insights["cohosted_domains"] = cohosted_count
                insights["ip_address"] = ip[0]
        
        conn.close()
        return insights
    
    def get_campaign_detection(self, domain: str) -> Optional[Dict]:
        """Bu domain bir campaign'in parçası mı?"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Domain pattern'lerini kontrol et
        # Örnek: aynı TLD, benzer isim yapısı, aynı IP bloğu
        
        # TLD bazlı campaign
        tld = domain.split('.')[-1]
        cursor.execute("""
            SELECT COUNT(*), AVG(risk_score) 
            FROM domain_analysis 
            WHERE tld = ? AND prediction = 1 AND timestamp > datetime('now', '-7 days')
        """, (tld,))
        
        tld_campaign_count, tld_avg_risk = cursor.fetchone()
        
        campaign_data = None
        
        # Eğer son 7 günde aynı TLD'den 5+ malicious domain varsa
        if tld_campaign_count and tld_campaign_count >= 5 and tld_avg_risk >= 70:
            campaign_data = {
                "type": "TLD-based Campaign",
                "tld": tld,
                "domain_count": tld_campaign_count,
                "avg_risk": round(tld_avg_risk, 2),
                "timeframe": "Last 7 days",
                "recommendation": f"⚠️ ALERT: .{tld} TLD'si aktif campaign'de kullanılıyor!"
            }
        
        conn.close()
        return campaign_data
    
    def get_statistics(self) -> Dict:
        """Sistem istatistikleri"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Toplam analiz
        cursor.execute("SELECT COUNT(*) FROM domain_analysis")
        total_analyses = cursor.fetchone()[0]
        
        # Malicious oranı
        cursor.execute("SELECT COUNT(*) FROM domain_analysis WHERE prediction = 1")
        malicious_count = cursor.fetchone()[0]
        
        # Son 24 saat
        cursor.execute("""
            SELECT COUNT(*) FROM domain_analysis 
            WHERE timestamp > datetime('now', '-1 day')
        """)
        last_24h = cursor.fetchone()[0]
        
        # En sık görülen TLD'ler
        cursor.execute("""
            SELECT tld, COUNT(*) as cnt 
            FROM domain_analysis 
            GROUP BY tld 
            ORDER BY cnt DESC 
            LIMIT 5
        """)
        top_tlds = cursor.fetchall()
        
        # High-risk IP'ler
        cursor.execute("""
            SELECT ip_address, domain_count 
            FROM ip_clusters 
            WHERE threat_level = 'HIGH' 
            ORDER BY domain_count DESC 
            LIMIT 5
        """)
        high_risk_ips = cursor.fetchall()
        
        conn.close()
        
        return {
            "total_analyses": total_analyses,
            "malicious_count": malicious_count,
            "malicious_rate": round((malicious_count / total_analyses * 100), 2) if total_analyses > 0 else 0,
            "last_24h_analyses": last_24h,
            "top_tlds": [{"tld": tld, "count": cnt} for tld, cnt in top_tlds],
            "high_risk_ips": [{"ip": ip, "domain_count": cnt} for ip, cnt in high_risk_ips]
        }
    
    def add_analyst_feedback(self, domain: str, feedback: str, is_false_positive: bool = False):
        """Analistin feedback'ini kaydet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE domain_analysis 
            SET analyst_feedback = ?, false_positive = ?
            WHERE domain = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (feedback, is_false_positive, domain))
        
        conn.commit()
        conn.close()
        
        print(f"✅ [Memory] Analyst feedback kaydedildi: {domain}")


# Singleton instance
memory_engine = ThreatMemoryEngine()


# ============================================================================
# SLACK KOMUTLARI İÇİN HELPER FUNCTIONS
# ============================================================================

def format_memory_insights(insights: Dict) -> str:
    """Memory insights in English"""
    if not insights.get("is_known"):
        return "ℹ️ *Memory:* First time analyzing this asset."
    
    text = f"🧠 *Threat Memory Insights*\n\n"
    text += f"• Previously analyzed: *{insights['analysis_count']} times*\n"
    text += f"• First seen: {insights['first_seen'][:10]}\n"
    text += f"• Last seen: {insights['last_seen'][:10]}\n"
    
    if insights.get("avg_risk_score"):
        text += f"• Avg Risk Score: {insights['avg_risk_score']}%\n"
    
    if insights.get("cohosted_domains"):
        text += f"• ⚠️ Co-hosted: {insights['cohosted_domains']} other domains detected on same IP!\n"
    
    return text


def format_similar_domains(similar: List[Dict]) -> str:
    """Benzer domain'leri Slack formatında döndür"""
    if not similar:
        return ""
    
    text = "\n🔍 *Benzer Domain'ler (Typosquatting Alert)*\n\n"
    for item in similar:
        text += f"• `{item['domain']}` - Benzerlik: {item['similarity']*100:.0f}% | Risk: {item['risk_score']}%\n"
    
    return text