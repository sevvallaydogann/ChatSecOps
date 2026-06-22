import os

env_icerik = """# ============================================================================
# CHATSECOPS V2 - ENVIRONMENTAL VARIABLES (CONFIG)
# ============================================================================

# --- SLACK CREDENTIALS ---
# Bot User OAuth Token (xoxb-...) - slack_bot.py'nin Slack ile konuşmasını sağlar
SLACK_BOT_TOKEN=
# App-Level Token (xapp-...) - Socket Mode bağlantısı için şarttır
SLACK_APP_TOKEN=
BACKEND_API_URL="http://localhost:8000"

# (Opsiyonel) Pivot zinciri bulgularının doğrudan iletileceği kanal webhook'u
SLACK_WEBHOOK_URL=""

# --- THREAT INTELLIGENCE & OSINT API KEYS ---
# VirusTotal v3 API Key
VIRUSTOTAL_API_KEY=
# AbuseIPDB v2 API Key
ABUSEIPDB_API_KEY=

# AlienVault OTX API Key
ALIENVAULT_API_KEY=

# Shodan API Key
SHODAN_API_KEY=	

# IPInfo Token (Co-location ve ASN tespiti için)
IPINFO_TOKEN=

# --- CORE AI GENERATIVE MODEL ---
# Google AI Studio Gemini API Key
GEMINI_API_KEY=
"""

# Dosyayı kök dizine yaz
try:
    with open(".env", "w", encoding="utf-8") as f:
        f.write(env_icerik)
    print("✅ [.env] Dosyası projenin kök dizininde başarıyla oluşturuldu!")
    print("💡 Şimdi tek yapman gereken VS Code içinden bu dosyayı açıp tırnak içindeki alanları kendi API anahtarlarınla doldurmak.")
except Exception as e:
    print(f"❌ Dosya oluşturulurken hata çıktı: {e}")