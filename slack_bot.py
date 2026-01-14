"""
ChatSecOps Slack Bot
Ayrı bir dosya olarak çalışır, main.py'den bağımsızdır.
Backend API (main.py) ile REST üzerinden haberleşir.

Çalıştırma:
    Terminal 1: uvicorn main:app --reload
    Terminal 2: python slack_bot.py
"""

import os
import requests
import re
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv
from ChatSecOps_Intelligence import intel_engine

# Ortam değişkenlerini yükle
load_dotenv()

# Slack App'i başlat
app = App(token=os.getenv("SLACK_BOT_TOKEN"))

# Backend API URL'i (main.py FastAPI sunucusu)
BACKEND_API = os.getenv("BACKEND_API_URL", "http://localhost:8000")

# --- YARDIMCI FONKSİYONLAR ---

def format_risk_message(data: dict) -> dict:
    """API yanıtını Slack mesaj formatına dönüştür"""
    domain = data.get("domain", "Bilinmiyor")
    ai_summary = data.get("ai_ozeti", "Analiz tamamlanamadı.")
    raw_data = data.get("ham_veriler", {})
    
    # LLM durumunu kontrol et
    llm_status = data.get("llm_status", "success")
    is_fallback = (llm_status == "fallback")
    
    # Kendi modelimizin sonuçları
    model_data = raw_data.get("kendi_modelimiz", {})
    risk_score = model_data.get("risk_skoru_yuzde", "N/A")
    detected_ip = model_data.get("tespit_edilen_ip", "N/A")
    country = model_data.get("tespit_edilen_ulke", "N/A")
    
    # Risk seviyesine göre emoji ve renk
    try:
        risk_num = float(risk_score.replace("%", ""))
        if risk_num >= 80:
            emoji = "🔴"
            color = "#d73a49"
            level = "KRİTİK"
        elif risk_num >= 50:
            emoji = "🟠"
            color = "#fb8500"
            level = "YÜKSEK"
        elif risk_num >= 20:
            emoji = "🟡"
            color = "#ffb700"
            level = "ORTA"
        else:
            emoji = "🟢"
            color = "#28a745"
            level = "DÜŞÜK"
    except:
        emoji = "⚪"
        color = "#586069"
        level = "BİLİNMİYOR"
    
    # VirusTotal sonucu
    vt_data = raw_data.get("virustotal", {})
    if "hata" not in vt_data:
        vt_malicious = vt_data.get("malicious", 0)
        vt_total = sum(vt_data.values())
        vt_status = f"{vt_malicious}/{vt_total} tespit"
    else:
        vt_status = "Sorgu başarısız"
    
    # AbuseIPDB sonucu
    abuse_data = raw_data.get("abuseipdb", {})
    if "hata" not in abuse_data:
        abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        abuse_reports = abuse_data.get("totalReports", 0)
        abuse_status = f"Güven Skoru: {abuse_score}% | Raporlar: {abuse_reports}"
    else:
        abuse_status = "Sorgu başarısız"
    
    # Slack mesaj bloklarını oluştur
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Tehdit Analiz Raporu: {domain}",
                "emoji": True
            }
        }
    ]
    screenshot_url = intel_engine.get_visual_evidence(domain)

    # BLOKLARI DAHA GÜVENLİ EKLEYELİM
    # Slack bazen resmi indiremezse hata verir, bu yüzden image bloğunu ayrı ekliyoruz
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"🌐 *Görsel Kanıt (Web Preview):* <{screenshot_url}|Görüntüyü Tarayıcıda Aç>"
        }
    })

    # İsteğe bağlı: Hala resim olarak denemek istersen ama hata riskini azaltmak için:
    blocks.append({
        "type": "image",
        "image_url": screenshot_url,
        "alt_text": "Site Preview"
    })
    
    # Eğer fallback modundaysa uyarı ekle
    if is_fallback:
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "⚠️ *LLM geçici olarak kullanılamıyor. Otomatik rapor oluşturuldu.*"
                }
            ]
        })
    
    blocks.extend([
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Risk Seviyesi:*\n{level}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*ML Risk Skoru:*\n{risk_score}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Tespit Edilen IP:*\n`{detected_ip}`"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Ülke:*\n{country}"
                }
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*📊 Harici Kaynak Verileri*\n\n*VirusTotal:* {vt_status}\n*AbuseIPDB:* {abuse_status}"
            }
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🤖 AI Analiz Özeti*\n\n{ai_summary}"
            }
        }
    ])
    
    return {
        "blocks": blocks,
        "text": f"Analiz Raporu: {domain} - Risk: {level}"
    }

# --- SLACK KOMUTLARI ---

@app.message("help")
@app.message("yardım")
def help_command(message, say):
    """Yardım mesajı"""
    help_text = """
🛡️ *ChatSecOps Mini-SOAR Komutları*

📝 *Kullanım:*
• `analyze <domain>` - Domain analizi yap
• `check <domain>` - Domain kontrolü
• `scan <domain>` - Domain taraması

💡 *Örnekler:*
• `analyze inetserv.pl`
• `check malicious-domain.com`
• `scan example.org`

❓ *Yardım:*
• `help` veya `yardım` - Bu mesajı göster
• `status` - Sistem durumu

---
_ChatSecOps v1.0 | Powered by LightGBM + Gemini AI_
    """
    say(help_text)

@app.message("status")
@app.message("durum")
def status_command(message, say):
    """Sistem durumu kontrolü"""
    try:
        response = requests.get(f"{BACKEND_API}/", timeout=5)
        if response.status_code == 200:
            say("✅ *Sistem Durumu:* Çevrimiçi ve Çalışıyor\n🔗 Backend API bağlantısı başarılı.")
        else:
            say("⚠️ *Sistem Durumu:* Backend API yanıt vermiyor.")
    except Exception as e:
        say(f"❌ *Sistem Durumu:* Bağlantı hatası\n```{str(e)}```")

@app.message("analyze")
@app.message("check")
@app.message("scan")
def analyze_domain(message, say):
    """Domain analizi yap"""
    text = message.get("text", "")
    words = text.split()
    
    if len(words) < 2:
        say("❌ *Hata:* Lütfen bir domain belirtin.")
        return
    
    # --- [YENİ: SLACK LİNK TEMİZLEME KODU] ---
    raw_domain = words[1].strip()
    # Slack linklerini temizle: <http://google.com|google.com> -> google.com
    domain = re.sub(r"<http[s]?://[^|]+\|([^>]+)>", r"\1", raw_domain)
    # Eğer link değil de düz metinse ama < > içindeyse yine temizle
    domain = domain.replace("<", "").replace(">", "").replace("http://", "").replace("https://", "")
    # ----------------------------------------

    say(f"🔍 *{domain}* analiz ediliyor, lütfen bekleyin...")
    
    try:
        # Backend API'ye istek gönder
        response = requests.get(
            f"{BACKEND_API}/enrich-and-summarize/domain/{domain}",
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            message_blocks = format_risk_message(data)
            say(**message_blocks)
        else:
            say(f"❌ *Analiz Hatası*\n```Status Code: {response.status_code}\n{response.text}```")
    
    except requests.exceptions.Timeout:
        say(f"⏱️ *Zaman Aşımı*\nAnaliz süresi çok uzun sürdü. Domain: `{domain}`")
    except Exception as e:
        say(f"❌ *Beklenmeyen Hata*\n```{str(e)}```")

# Bot'a mention edildiğinde
@app.event("app_mention")
def handle_mention(event, say):
    """Bot'a mention edildiğinde otomatik cevap"""
    text = event.get("text", "").lower()
    
    if "help" in text or "yardım" in text:
        help_command(event, say)
    elif "status" in text or "durum" in text:
        status_command(event, say)
    else:
        say(f"👋 Merhaba! Domain analizi için `analyze <domain>` komutunu kullanın.\nYardım için: `help`")

# --- ANA PROGRAM ---

if __name__ == "__main__":
    print("🚀 ChatSecOps Slack Bot başlatılıyor...")
    print(f"🔗 Backend API: {BACKEND_API}")
    
    # Socket Mode ile başlat (firewall arkasında çalışır)
    handler = SocketModeHandler(app, os.getenv("SLACK_APP_TOKEN"))
    
    print("✅ Bot hazır! Slack workspace'inizde komutları kullanabilirsiniz.")
    print("📝 Komutlar: analyze, check, scan, help, status")
    
    handler.start()