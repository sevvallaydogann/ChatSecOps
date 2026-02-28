"""
ChatSecOps_Memory.py - Optimized Database Schema
Changes:
- Added indexes for fast queries
- WAL mode for concurrent access
- Proper timestamp types
- Query optimization
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
import json
from difflib import SequenceMatcher

class ThreatMemoryEngine:
    """
    OPTIMIZED: Production-ready database design
    """
    
    def __init__(self, db_path: str = "chatsecops_memory.db"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize database with optimizations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enable WAL mode (Write-Ahead Logging) for concurrent access
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")  # Performance boost
        cursor.execute("PRAGMA cache_size=10000")     # 10MB cache
        
        # Main analysis table (UPDATED: INTEGER timestamp)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
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
        
        # === CRITICAL: Add indexes for fast queries ===
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_domain 
            ON domain_analysis(domain)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON domain_analysis(timestamp DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip 
            ON domain_analysis(ip_address)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_prediction 
            ON domain_analysis(prediction, timestamp)
        """)
        
        # Domain similarity (with index)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_similarity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain1 TEXT,
                domain2 TEXT,
                similarity_score REAL,
                detected_at INTEGER
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sim_domain1 
            ON domain_similarity(domain1)
        """)
        
        # IP clusters (UPDATED)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ip_clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                domain_count INTEGER DEFAULT 1,
                first_seen INTEGER,
                last_seen INTEGER,
                threat_level TEXT
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ip_threat 
            ON ip_clusters(threat_level, domain_count DESC)
        """)
        
        # Campaign tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_campaigns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                campaign_name TEXT,
                indicators TEXT,
                domain_count INTEGER,
                created_at INTEGER,
                last_activity INTEGER
            )
        """)
        
        conn.commit()
        conn.close()
        print("✅ [Memory] Optimized database ready with indexes")
    
    def store_analysis(self, domain: str, analysis_data: dict):
        """Store analysis with proper timestamp"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Parse data
        model_data = analysis_data.get("ham_veriler", {}).get("kendi_modelimiz", {})
        vt_data = analysis_data.get("ham_veriler", {}).get("virustotal", {})
        abuse_data = analysis_data.get("ham_veriler", {}).get("abuseipdb", {})
        
        risk_score = float(model_data.get("risk_skoru_yuzde", "0").replace("%", ""))
        prediction = model_data.get("tahmin_sinifi", 0)
        ip_address = model_data.get("tespit_edilen_ip", "N/A")
        country = model_data.get("tespit_edilen_ulke", "N/A")
        
        # XAI summary
        xai_data = model_data.get("xai_aciklama", {})
        xai_summary = json.dumps(xai_data) if xai_data else None
        
        tld = domain.split('.')[-1] if '.' in domain else 'unknown'
        
        # UPDATED: Use UNIX timestamp (integer)
        timestamp_unix = int(datetime.now().timestamp())
        
        cursor.execute("""
            INSERT INTO domain_analysis 
            (domain, timestamp, risk_score, prediction, ip_address, country, 
             tld, vt_malicious, abuse_score, xai_summary, full_analysis)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            timestamp_unix,
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
        
        # Update IP cluster
        self._update_ip_cluster(cursor, ip_address, domain, risk_score)
        
        # Find similar domains
        similar_domains = self._find_similar_domains(cursor, domain)
        
        conn.commit()
        conn.close()
        
        print(f"✅ [Memory] {domain} stored (Risk: {risk_score}%)")
        
        return {
            "stored": True,
            "similar_domains": similar_domains,
            "memory_insights": self.get_domain_insights(domain)
        }
    
    def _update_ip_cluster(self, cursor, ip_address: str, domain: str, risk_score: float):
        """Update IP clustering (Fixed UPSERT pattern)"""
        if ip_address == "N/A":
            return
        
        threat_level = "HIGH" if risk_score >= 80 else "MEDIUM" if risk_score >= 50 else "LOW"
        timestamp_unix = int(datetime.now().timestamp())
        
        # Check if IP exists
        cursor.execute("SELECT id, domain_count FROM ip_clusters WHERE ip_address = ?", (ip_address,))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing record
            cursor.execute("""
                UPDATE ip_clusters 
                SET domain_count = domain_count + 1,
                    last_seen = ?,
                    threat_level = ?
                WHERE ip_address = ?
            """, (timestamp_unix, threat_level, ip_address))
        else:
            # Insert new record
            cursor.execute("""
                INSERT INTO ip_clusters (ip_address, domain_count, first_seen, last_seen, threat_level)
                VALUES (?, 1, ?, ?, ?)
            """, (ip_address, timestamp_unix, timestamp_unix, threat_level))
    
    def _find_similar_domains(self, cursor, domain: str, threshold: float = 0.7) -> List[Dict]:
        """Find similar domains (typosquatting)"""
        
        # OPTIMIZED: Only check domains from last 90 days
        cutoff_time = int((datetime.now().timestamp() - 90*24*3600))
        
        cursor.execute("""
            SELECT domain, risk_score 
            FROM domain_analysis 
            WHERE domain != ? AND timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 500
        """, (domain, cutoff_time))
        
        recent_domains = cursor.fetchall()
        
        similar = []
        for stored_domain, risk_score in recent_domains:
            similarity = self._calculate_similarity(domain, stored_domain)
            if similarity >= threshold:
                similar.append({
                    "domain": stored_domain,
                    "similarity": round(similarity, 2),
                    "risk_score": risk_score
                })
                
                # Store similarity record
                timestamp_unix = int(datetime.now().timestamp())
                cursor.execute("""
                    INSERT INTO domain_similarity (domain1, domain2, similarity_score, detected_at)
                    VALUES (?, ?, ?, ?)
                """, (domain, stored_domain, similarity, timestamp_unix))
        
        return similar[:5]
    
    def _calculate_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate domain similarity"""
        name1 = '.'.join(domain1.split('.')[:-1])
        name2 = '.'.join(domain2.split('.')[:-1])
        return SequenceMatcher(None, name1, name2).ratio()
    
    def get_domain_insights(self, domain: str) -> Dict:
        """Get insights with optimized query (FIXED: timestamp handling)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Single optimized query
        cursor.execute("""
            SELECT 
                COUNT(*) as count,
                AVG(risk_score) as avg_risk,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                ip_address
            FROM domain_analysis 
            WHERE domain = ?
        """, (domain,))
        
        row = cursor.fetchone()
        
        if row and row[0] > 0:
            count, avg_risk, first_seen, last_seen, ip_addr = row
            
            # CRITICAL FIX: Handle both string and integer timestamps
            def safe_timestamp_convert(ts_value):
                """Convert timestamp to ISO format, handling both string and int"""
                if ts_value is None:
                    return None
                try:
                    # Try as integer (UNIX timestamp)
                    if isinstance(ts_value, (int, float)):
                        return datetime.fromtimestamp(ts_value).isoformat()
                    # Try as string (ISO format or UNIX string)
                    elif isinstance(ts_value, str):
                        # Check if it's already ISO format
                        if 'T' in ts_value or '-' in ts_value:
                            return ts_value  # Already ISO
                        # Try to convert string to int (UNIX timestamp as string)
                        return datetime.fromtimestamp(int(float(ts_value))).isoformat()
                    return None
                except (ValueError, TypeError, OSError):
                    return None
            
            insights = {
                "is_known": True,
                "analysis_count": count,
                "avg_risk_score": round(avg_risk, 2) if avg_risk else None,
                "first_seen": safe_timestamp_convert(first_seen),
                "last_seen": safe_timestamp_convert(last_seen)
            }
            
            # Co-hosted domains check
            if ip_addr and ip_addr != "N/A":
                cursor.execute("""
                    SELECT COUNT(DISTINCT domain) 
                    FROM domain_analysis 
                    WHERE ip_address = ? AND domain != ?
                """, (ip_addr, domain))
                
                cohosted = cursor.fetchone()[0]
                insights["cohosted_domains"] = cohosted
                insights["ip_address"] = ip_addr
        else:
            insights = {"is_known": False, "analysis_count": 0}
        
        conn.close()
        return insights
    
    def get_campaign_detection(self, domain: str) -> Optional[Dict]:
        """
        Detect if this domain is part of a campaign
        Checks TLD-based campaigns and similar patterns
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Extract TLD
        tld = domain.split('.')[-1] if '.' in domain else 'unknown'
        
        # Check for TLD-based campaign (last 7 days)
        week_ago = int(datetime.now().timestamp() - 7*86400)
        
        cursor.execute("""
            SELECT COUNT(*), AVG(risk_score) 
            FROM domain_analysis 
            WHERE tld = ? AND prediction = 1 AND timestamp > ?
        """, (tld, week_ago))
        
        tld_campaign_count, tld_avg_risk = cursor.fetchone()
        
        campaign_data = None
        
        # If 5+ malicious domains with same TLD in last 7 days
        if tld_campaign_count and tld_campaign_count >= 5 and tld_avg_risk >= 70:
            campaign_data = {
                "type": "TLD-based Campaign",
                "tld": tld,
                "domain_count": tld_campaign_count,
                "avg_risk": round(tld_avg_risk, 2),
                "timeframe": "Last 7 days",
                "recommendation": f"⚠️ ALERT: .{tld} TLD is being actively used in a campaign!"
            }
        
        conn.close()
        return campaign_data
    
    def get_statistics(self) -> Dict:
        """Get system statistics (OPTIMIZED)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total analyses
        cursor.execute("SELECT COUNT(*) FROM domain_analysis")
        total = cursor.fetchone()[0]
        
        # Malicious count
        cursor.execute("SELECT COUNT(*) FROM domain_analysis WHERE prediction = 1")
        malicious = cursor.fetchone()[0]
        
        # Last 24h (UNIX timestamp)
        cutoff = int(datetime.now().timestamp() - 24*3600)
        cursor.execute("SELECT COUNT(*) FROM domain_analysis WHERE timestamp > ?", (cutoff,))
        last_24h = cursor.fetchone()[0]
        
        # Top TLDs
        cursor.execute("""
            SELECT tld, COUNT(*) as cnt 
            FROM domain_analysis 
            GROUP BY tld 
            ORDER BY cnt DESC 
            LIMIT 5
        """)
        top_tlds = [{"tld": row[0], "count": row[1]} for row in cursor.fetchall()]
        
        # High-risk IPs
        cursor.execute("""
            SELECT ip_address, domain_count 
            FROM ip_clusters 
            WHERE threat_level = 'HIGH' 
            ORDER BY domain_count DESC 
            LIMIT 5
        """)
        high_risk_ips = [{"ip": row[0], "domain_count": row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "total_analyses": total,
            "malicious_count": malicious,
            "malicious_rate": round((malicious / total * 100), 2) if total > 0 else 0,
            "last_24h_analyses": last_24h,
            "top_tlds": top_tlds,
            "high_risk_ips": high_risk_ips
        }


# Singleton
memory_engine = ThreatMemoryEngine()


# === Helper functions (keep existing) ===
def format_memory_insights(insights: Dict) -> str:
    """Format memory insights for Slack"""
    if not insights.get("is_known"):
        return "ℹ️ *Memory:* First time analyzing this asset."
    
    text = f"🧠 *Threat Memory Insights*\n\n"
    text += f"• Previously analyzed: *{insights['analysis_count']} times*\n"
    text += f"• First seen: {insights['first_seen'][:10]}\n"
    text += f"• Last seen: {insights['last_seen'][:10]}\n"
    
    if insights.get("avg_risk_score"):
        text += f"• Avg Risk Score: {insights['avg_risk_score']}%\n"
    
    if insights.get("cohosted_domains"):
        text += f"• ⚠️ Co-hosted: {insights['cohosted_domains']} other domains on same IP!\n"
    
    return text


def format_similar_domains(similar: List[Dict]) -> str:
    """Format similar domains for Slack"""
    if not similar:
        return ""
    
    text = "\n🔍 *Similar Domains (Typosquatting Alert)*\n\n"
    for item in similar:
        text += f"• `{item['domain']}` - Similarity: {item['similarity']*100:.0f}% | Risk: {item['risk_score']}%\n"
    
    return text