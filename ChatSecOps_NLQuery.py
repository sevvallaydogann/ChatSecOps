"""
ChatSecOps_NLQuery.py - Doğal Dil Sorgu Motoru (Feature 4)
=========================================================
Kullanıcının Slack'te yazdığı doğal dil sorusunu:
  1. Gemini ile SQL'e çevirir
  2. SQLite'ta güvenli şekilde çalıştırır
  3. Sonucu Gemini ile okunabilir Türkçe yanıta dönüştürür

Kullanım:
  from ChatSecOps_NLQuery import nl_query_engine
  result = nl_query_engine.ask("Son 7 günde kaç malicious domain var?")
"""

import sqlite3
import logging
import re
import google.generativeai as genai
import os
from datetime import datetime
from dotenv import load_dotenv

# .env dosyasını kod seviyesinde zorla yükle
load_dotenv()

logger = logging.getLogger(__name__)

# =============================================================================
# GERÇEK VERİTABANI ŞEMASI
# Bu bilgi Gemini'ye verilir — tablolar ve kolonlar doğru olmalı.
# =============================================================================

DB_SCHEMA = """
Sen ChatSecOps'un SOC Asistanısın. Aşağıda veritabanının gerçek şeması var.

=== TABLO: domain_analysis ===
Her domain analizi bu tabloya kaydedilir.
  id             INTEGER  - Otomatik artan birincil anahtar
  domain         TEXT     - Analiz edilen domain adı (örn: "google.com")
  timestamp      INTEGER  - Unix timestamp (saniye cinsinden) 
  risk_score     REAL     - ML modelinin ürettiği risk skoru (0.0 - 100.0)
  prediction     INTEGER  - 0 = Güvenli (SAFE), 1 = Zararlı (MALICIOUS)
  ip_address     TEXT     - Domain'in IP adresi
  country        TEXT     - IP'nin ülkesi
  tld            TEXT     - Üst düzey alan adı (com, net, tk, ru vb.)
  vt_malicious   INTEGER  - VirusTotal'da kaç motor zararlı dedi
  abuse_score    REAL     - AbuseIPDB güven skoru (0-100)
  xai_summary    TEXT     - SHAP açıklama özeti (JSON)
  full_analysis  JSON     - Tüm ham veriler
  false_positive BOOLEAN  - 0 = Gerçek tehdit, 1 = Yanlış alarm

=== TABLO: ip_clusters ===
Aynı IP'yi paylaşan domain grupları.
  ip_address     TEXT     - IP adresi (UNIQUE)
  domain_count   INTEGER  - Bu IP üzerinde kaç domain analiz edildi
  first_seen     INTEGER  - İlk görülme Unix timestamp
  last_seen      INTEGER  - Son görülme Unix timestamp
  threat_level   TEXT     - "HIGH", "MEDIUM", "LOW"

=== TABLO: domain_similarity ===
Birbirine benzeyen domain çiftleri (typosquatting tespiti).
  domain1          TEXT  - Referans domain
  domain2          TEXT  - Benzer domain
  similarity_score REAL  - 0.0 - 1.0 arası benzerlik (1.0 = aynı)
  detected_at      INTEGER - Tespit zamanı Unix timestamp

=== TABLO: threat_campaigns ===
Kampanya takibi.
  campaign_name  TEXT     - Kampanya adı
  indicators     TEXT     - Göstergeler
  domain_count   INTEGER  - Kampanyaya dahil domain sayısı
  created_at     INTEGER  - Oluşturma zamanı
  last_activity  INTEGER  - Son aktivite zamanı

=== ZAMAN İFADELERİ (ÖNEMLİ) ===
timestamp kolonu Unix timestamp'tir (INTEGER).
- "Son 24 saat"  → timestamp > strftime('%s','now','-1 day')
- "Son 7 gün"    → timestamp > strftime('%s','now','-7 days')
- "Son 30 gün"   → timestamp > strftime('%s','now','-30 days')
- "Bu ay"        → timestamp > strftime('%s','now','start of month')

=== ÖRNEK SORGULAR ===
Soru: "Kaç domain analiz edildi?"
SQL: SELECT COUNT(*) FROM domain_analysis

Soru: "En riskli 5 domain hangisi?"
SQL: SELECT domain, risk_score FROM domain_analysis ORDER BY risk_score DESC LIMIT 5

Soru: "Son 7 günde kaç zararlı domain tespit edildi?"
SQL: SELECT COUNT(*) FROM domain_analysis WHERE prediction = 1 AND timestamp > strftime('%s','now','-7 days')

Soru: "Hangi ülkelerden tehdit geliyor?"
SQL: SELECT country, COUNT(*) as sayi FROM domain_analysis WHERE prediction = 1 GROUP BY country ORDER BY sayi DESC LIMIT 10

Soru: "En çok hangi TLD zararlı?"
SQL: SELECT tld, COUNT(*) as sayi FROM domain_analysis WHERE prediction = 1 GROUP BY tld ORDER BY sayi DESC LIMIT 5

Soru: "Aynı IP'yi paylaşan en tehlikeli gruplar?"
SQL: SELECT ip_address, domain_count, threat_level FROM ip_clusters WHERE threat_level = 'HIGH' ORDER BY domain_count DESC LIMIT 5

=== KURALLARIN TAMAMI ===
- Sadece SELECT sorguları üret. INSERT, UPDATE, DELETE, DROP yasak.
- Yanıt olarak SADECE SQL yaz — Pediatric hiçbir şey yok.
- Markdown (```sql) kullanma, düz metin SQL ver.
- Tablolardan sadece yukarıda belirtilenleri kullan.
"""

# =============================================================================
# GÜVENLİ SQL VALİDATÖRÜ
# Gemini bazen UPDATE veya DROP üretebilir — bunu engelliyoruz.
# =============================================================================

FORBIDDEN_KEYWORDS = [
    "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
    "CREATE", "TRUNCATE", "REPLACE", "ATTACH", "DETACH"
]

def is_safe_sql(sql: str) -> bool:
    """Üretilen SQL'in sadece SELECT olduğunu doğrular."""
    sql_upper = sql.upper().strip()
    
    # SELECT ile başlamalı
    if not sql_upper.startswith("SELECT"):
        return False
    
    # Tehlikeli anahtar kelimeler içermemeli
    for keyword in FORBIDDEN_KEYWORDS:
        if re.search(r'\b' + keyword + r'\b', sql_upper):
            logger.warning(f"[NLQUERY] Tehlikeli SQL engellendi: '{keyword}' bulundu")
            return False
    
    return True


# =============================================================================
# SORGU MOTORU
# =============================================================================

class NLQueryEngine:
    """
    Doğal dil → SQL → Sonuç → Okunabilir yanıt
    """
    
    def __init__(self, db_path: str = "chatsecops_memory.db"):
        self.db_path = db_path
        self.gemini_model = None
        self._init_gemini()
    
    def _init_gemini(self):
        """Gemini modelini başlat."""
        try:
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                logger.error("[NLQUERY] GEMINI_API_KEY bulunamadı")
                return
            
            genai.configure(api_key=api_key)
            
            # DÜZELTME: En güncel ve çalışan stabil model en başa eklendi
            model_candidates = [
                "models/gemini-2.5-flash",
                "models/gemini-2.5-flash-preview-05-20",
                "models/gemini-1.5-flash-latest",
                "models/gemini-1.5-flash",
                "models/gemini-pro"
            ]
            
            for model_name in model_candidates:
                try:
                    m = genai.GenerativeModel(model_name)
                    m.generate_content("test")
                    self.gemini_model = m
                    logger.info(f"✅ [NLQUERY] Gemini hazır: {model_name}")
                    break
                except Exception:
                    continue
                    
            if not self.gemini_model:
                logger.error("[NLQUERY] Hiçbir Gemini modeli yüklenemedi")
                
        except Exception as e:
            logger.error(f"[NLQUERY] Gemini başlatma hatası: {e}")
    
    def _generate_sql(self, user_question: str) -> str:
        """
        Gemini'ye şemayı + soruyu ver, SQL üret.
        Returns: SQL string veya hata durumunda None
        """
        if not self.gemini_model:
            return None
        
        prompt = f"""{DB_SCHEMA}

Kullanıcı Sorusu: "{user_question}"
SQL Sorgusu:"""
        
        try:
            response = self.gemini_model.generate_content(prompt)
            sql = response.text.strip()
            
            # Markdown temizle
            sql = sql.replace("```sql", "").replace("```", "").strip()
            
            # Noktalı virgülü kaldır
            sql = sql.rstrip(";").strip()
            
            logger.info(f"[NLQUERY] Üretilen SQL: {sql}")
            return sql
            
        except Exception as e:
            logger.error(f"[NLQUERY] SQL üretim hatası: {e}")
            return None
    
    def _execute_sql(self, sql: str) -> tuple:
        """
        SQL'i SQLite'ta güvenli çalıştır.
        """
        if not is_safe_sql(sql):
            return None, "Güvenlik kontrolü: Bu sorgu türüne izin verilmiyor."
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            column_names = [desc[0] for desc in cursor.description] if cursor.description else []
            conn.close()
            
            rows_as_dicts = [dict(row) for row in rows]
            logger.info(f"[NLQUERY] Sorgu başarılı: {len(rows_as_dicts)} satır döndü")
            return rows_as_dicts, column_names
            
        except sqlite3.OperationalError as e:
            logger.error(f"[NLQUERY] SQL çalıştırma hatası: {e}")
            return None, f"Veritabanı hatası: {str(e)}"
        except Exception as e:
            logger.error(f"[NLQUERY] Beklenmeyen hata: {e}")
            return None, str(e)
    
    def _format_response(self, user_question: str, rows: list, columns: list) -> str:
        """
        Ham veritabanı sonucunu Gemini ile okunabilir yanıta dönüştür.
        """
        if not self.gemini_model:
            if not rows:
                return "📭 Bu sorgu için veritabanında kayıt bulunamadı."
            return f"📊 Sorgu sonucu ({len(rows)} kayıt):\n" + "\n".join(str(r) for r in rows[:10])
        
        if not rows:
            return "📭 Bu sorgu için veritabanında herhangi bir kayıt bulunamadı."
        
        display_rows = rows[:20]
        truncated = len(rows) > 20
        
        prompt = f"""Sen ChatSecOps'un SOC Asistanısın. Kullanıcıya veritabanı sorgu sonuçlarını yorumlayarak yanıt ver.

Kullanıcının Sorusu: "{user_question}"

Veritabanından Gelen Ham Veri:
Kolonlar: {columns}
Satırlar: {display_rows}
{"(Not: İlk 20 satır gösteriliyor, toplam " + str(len(rows)) + " kayıt var)" if truncated else ""}

Lütfen şu kurallara göre yanıt yaz:
- Türkçe yaz
- Profesyonel ama anlaşılır bir SOC analisti dili kullan
- Sayısal verileri öne çıkar
- Önemli bulgular varsa vurgula (örn: çok sayıda zararlı domain, riskli IP)
- 2-4 cümle yeterli
- Emoji kullanabilirsin (📊 🔴 ⚠️ ✅)
- Sadece yanıtı yaz, başka bir şey ekleme
"""
        
        try:
            response = self.gemini_model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            logger.error(f"[NLQUERY] Yanıt formatı hatası: {e}")
            lines = [f"📊 *Sorgu Sonucu* ({len(rows)} kayıt):"]
            for row in display_rows[:10]:
                lines.append("• " + " | ".join(f"{k}: {v}" for k, v in row.items()))
            return "\n".join(lines)
    
    def ask(self, user_question: str) -> dict:
        """
        Ana giriş noktası. Soru alır, yanıt döner.
        """
        logger.info(f"[NLQUERY] Soru: {user_question}")
        
        if not self.gemini_model:
            return {
                "answer": "❌ AI modeli şu an aktif değil. Lütfen sistem yöneticisiyle iletişime geçin.",
                "sql": None,
                "row_count": 0,
                "success": False
            }
        
        sql = self._generate_sql(user_question)
        if not sql:
            return {
                "answer": "❌ Sorunuz SQL sorgusuna çevrilemedi. Daha açık bir soru sormayı deneyin.",
                "sql": None,
                "row_count": 0,
                "success": False
            }
        
        rows, columns_or_error = self._execute_sql(sql)
        
        if rows is None:
            logger.error(f"[NLQUERY] SQL başarısız: {columns_or_error}")
            try:
                fallback_prompt = f"""Sen ChatSecOps SOC Asistanısın. 
Kullanıcı şunu sordu: "{user_question}"
Veritabanı sorgusu çalışırken teknik hata oluştu.
Kullanıcıya kısa, kibar, Türkçe bir hata mesajı yaz. SQL detayı verme."""
                fallback = self.gemini_model.generate_content(fallback_prompt).text.strip()
                return {
                    "answer": fallback,
                    "sql": sql,
                    "row_count": 0,
                    "success": False
                }
            except:
                return {
                    "answer": f"⚠️ Sorgu çalıştırılırken hata oluştu. Farklı bir soru deneyin.",
                    "sql": sql,
                    "row_count": 0,
                    "success": False
                }
        
        formatted_answer = self._format_response(user_question, rows, columns_or_error)
        
        return {
            "answer": formatted_answer,
            "sql": sql,
            "row_count": len(rows),
            "success": True
        }

# =============================================================================
# SİNGLETON
# =============================================================================
nl_query_engine = NLQueryEngine()