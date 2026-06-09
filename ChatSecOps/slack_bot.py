"""
slack_bot.py - FINAL HYBRID VERSION
Combines the stability of the old bot with the new features (Shodan/OTX/English).
"""
import os
import requests
import re
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv
from ChatSecOps_NLQuery import nl_query_engine

# Load Environment Variables
load_dotenv()

# Initialize Slack App
app = App(token=os.getenv("SLACK_BOT_TOKEN"))

# Backend API URL
BACKEND_API = os.getenv("BACKEND_API_URL", "http://localhost:8000")

# ============================================================================
# HELPER: MESSAGE FORMATTER
# ============================================================================

def format_risk_message(data: dict) -> dict:
    """
    Converts API response into a professional Slack message block.
    Includes: VirusTotal, AbuseIPDB, AlienVault, Shodan, ML, and PDF Buttons.
    """
    domain = data.get("domain", "Unknown")
    
    # --- 1. AI Summary Handling ---
    ai_raw = data.get("ai_ozeti", {})
    if isinstance(ai_raw, dict):
        # If fallback dictionary
        verdict = ai_raw.get("verdict", "UNKNOWN")
        risk_score = ai_raw.get("risk_score", "N/A")
        action = ai_raw.get("action", "REVIEW")
        ai_text = ai_raw.get("xai_output", "Analysis unavailable.")
    else:
        # If genuine Gemini text
        verdict = "ANALYZED"
        risk_score = "See Below"
        action = "CHECK REPORT"
        ai_text = str(ai_raw)

    # --- 2. Technical Data Extraction ---
    raw = data.get("ham_veriler", {})
    model_data = raw.get("kendi_modelimiz", {})
    vt_data = raw.get("virustotal", {})
    abuse_data = raw.get("abuseipdb", {})
    osint_data = raw.get("osint", {}) # NEW: AlienVault & Shodan

    # ML Specifics
    ml_risk = model_data.get("risk_skoru_yuzde", "0%")
    detected_ip = model_data.get("tespit_edilen_ip", "N/A")
    country = model_data.get("tespit_edilen_ulke", "Unknown")

    # --- 3. Status Indicators & Logic ---
    
    # Risk Color Logic (Based on your old code preferences)
    try:
        risk_num = float(ml_risk.replace("%", ""))
        if risk_num >= 80:
            emoji = "🔴"
            color = "#d73a49" # Red
            verdict = "CRITICAL"
        elif risk_num >= 50:
            emoji = "🟠"
            color = "#fb8500" # Orange
            verdict = "HIGH"
        elif risk_num >= 20:
            emoji = "🟡"
            color = "#ffb700" # Yellow
            verdict = "MEDIUM"
        else:
            emoji = "🟢"
            color = "#28a745" # Green
            verdict = "SAFE"
    except:
        emoji = "⚪"
        color = "#586069"

    # VirusTotal Status
    if "hata" not in vt_data and vt_data:
        vt_mal = vt_data.get("malicious", 0)
        vt_total = sum(vt_data.values())
        vt_icon = "🔴" if vt_mal > 0 else "✅"
        vt_status = f"{vt_icon} {vt_mal}/{vt_total} flagged"
    else:
        vt_status = "⚪ Data Unavailable"

    # AlienVault Status (NEW)
    av = osint_data.get("alienvault", {})
    if av and not av.get("error"):
        av_count = av.get("pulse_count", 0)
        av_icon = "🔴" if av_count > 0 else "✅"
        av_status = f"{av_icon} {av_count} Pulses"
    else:
        av_status = "⚪ N/A"

    # Shodan Status (NEW)
    sho = osint_data.get("shodan", {})
    if sho and not sho.get("error"):
        ports = len(sho.get("ports", []))
        vulns = len(sho.get("vulns", []))
        sho_icon = "⚠️" if vulns > 0 else "ℹ️"
        sho_status = f"{sho_icon} Ports: {ports} | Vulns: {vulns}"
    else:
        if detected_ip == "N/A" or not detected_ip:
            sho_status = "⚪ No IP Resolved"
        else:
            sho_status = "⚪ Not Found"

    # --- 4. Build Message Blocks ---
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Security Report: {domain}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Verdict:*\n{verdict}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n{ml_risk}"},
                {"type": "mrkdwn", "text": f"*IP Address:*\n`{detected_ip}`"},
                {"type": "mrkdwn", "text": f"*Location:*\n{country}"}
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🔬 Threat Intelligence Feeds*"
            },
            "fields": [
                {"type": "mrkdwn", "text": f"*VirusTotal:*\n{vt_status}"},
                {"type": "mrkdwn", "text": f"*AbuseIPDB:*\nScore: {abuse_data.get('abuseConfidenceScore', 'N/A')}%"},
                {"type": "mrkdwn", "text": f"*AlienVault OTX:*\n{av_status}"},
                {"type": "mrkdwn", "text": f"*Shodan:*\n{sho_status}"}
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*🤖 AI Analysis Summary*\n{ai_text[:600]}..." # Truncate if too long
            }
        }
    ]
    try:
        img_url = f"https://image.thum.io/get/width/600/crop/800/noanimate/http://{domain}"
        blocks.append({
            "type": "image",
            "image_url": img_url,
            "alt_text": "site_preview",
            "title": {"type": "plain_text", "text": "🌍 Live Site Preview"}
        })
    except:
        pass

    # --- 5. Add Action Buttons (PDF & Graph) ---
    actions = []
    if data.get("pdf_report"):
        actions.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📄 Download PDF"},
            "value": data["pdf_report"],
            "action_id": "download_pdf"
        })
    
    if data.get("shap_graph"):
        actions.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📊 Technical Graph"},
            "value": data["shap_graph"],
            "action_id": "show_graph"
        })

    if actions:
        blocks.append({"type": "actions", "elements": actions})

    return {
        "text": f"Report for {domain}: {verdict}",
        "blocks": blocks,
        "attachments": [{"color": color, "blocks": []}]
    }

# ============================================================================
# COMMAND HANDLERS
# ============================================================================

# Düzeltme: Tam kelime eşleşmesi (Regex) kullanarak help çakışmasını engelliyoruz
@app.message(re.compile(r"^help$", re.IGNORECASE))
def help_command(message, say):
    """English Help Menu"""
    help_text = """
🛡️ *ChatSecOps SOAR - Command Menu*
 
*🔍 Analysis Commands:*
• `analyze <domain>` - Full security scan (VT, Shodan, OTX, AI)
• `check <domain>` - Quick check
• `scan <domain>` - Deep scan
 
*🤖 AI Query Interface (Feature 4):*
• `query <soru>` - Veritabanına doğal dille sor
• `ask <soru>` - Aynı işlev (İngilizce alternatif)
 
*Örnek query komutları:*
• `query Son 7 günde kaç zararlı domain var?`
• `query En riskli 5 domain hangisi?`
• `query Hangi ülkelerden tehdit geliyor?`
• `query En çok hangi TLD zararlı?`
• `query Aynı IP'yi paylaşan gruplar?`
 
*📊 System:*
• `stats` - View threat statistics
• `status` - Check API connectivity
 
*💡 Example:*
`analyze google.com`
    """
    say(help_text)

@app.message(re.compile(r"^status$", re.IGNORECASE))
def status_command(message, say):
    """System Health Check"""
    try:
        response = requests.get(f"{BACKEND_API}/", timeout=5)
        if response.status_code == 200:
            say("✅ *System Status:* Online & Operational\n🔗 Backend API connected.")
        else:
            say("⚠️ *System Status:* Backend API reachable but returned error.")
    except Exception as e:
        say(f"❌ *System Status:* Connection Failed\n```{str(e)}```")

@app.message(re.compile(r"^stats$", re.IGNORECASE))
def statistics_command(message, say):
    """System Statistics"""
    try:
        response = requests.get(f"{BACKEND_API}/statistics", timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            msg = f"📊 *System Statistics*\n• Total Scans: {data.get('total_analyses', 0)}\n• Malicious: {data.get('malicious_count', 0)}"
            say(msg)
        else:
            say("❌ Stats unavailable.")
    except:
        say("❌ Stats error.")

# Düzeltme: Komutların mesajın başında olduğunu garanti altına alan ve çakışmayan Regex yapısı
@app.message(re.compile(r"^(analyze|check|scan)\s+(.*)", re.IGNORECASE))
def analyze_domain(message, say):
    """Main Analysis Handler"""
    text = message.get("text", "").strip()
    
    match = re.match(r"^(analyze|check|scan)\s+(.*)", text, re.IGNORECASE)
    if not match:
        say("❌ *Error:* Please specify a domain.\n*Example:* `analyze example.com`")
        return
        
    raw_domain = match.group(2).strip()
    
    # Cleanup domain format (remove < > | from Slack links)
    domain = re.sub(r"<http[s]?://[^|]+\|([^>]+)>", r"\1", raw_domain)
    domain = domain.replace("<", "").replace(">", "").replace("http://", "").replace("https://", "").split("/")[0]
    
    say(f"🔍 Analyzing *{domain}*... Please wait.")
    
    try:
        # Call Backend
        response = requests.get(
            f"{BACKEND_API}/enrich-and-summarize/domain/{domain}",
            timeout=90
        )
        
        if response.status_code == 200:
            data = response.json()
            message_blocks = format_risk_message(data)
            say(**message_blocks)
            
            if pivot.get("triggered") and pivot.get("total_related", 0) > 0:
                   say(f"🕸️ *Pivot Zinciri:* Bu IP üzerinde "
                        f"{pivot['total_related']} ilişkili domain tespit edildi. "
                        f"{pivot.get('auto_analyzed_count', 0)} yeni domain otomatik analiz edildi.")  
            
            # Memory Insight
            mem = data.get("memory_insights", {})
            if mem.get("is_known"):
                say(f"🧠 *Memory:* This domain was analyzed {mem['analysis_count']} times before.")
        else:
            say(f"❌ *Analysis Failed*\nStatus: {response.status_code}")
            
    except requests.exceptions.Timeout:
        say(f"⏱️ *Timeout:* Analysis took too long.")
    except Exception as e:
        say(f"❌ *Error:* {str(e)}")

@app.message(re.compile(r"^(query|ask|sor)\s+(.*)", re.IGNORECASE))
def handle_nl_query(message, say):
    """
    Feature 4: Doğal Dil Sorgu Arayüzü
    Kullanım: query <soru>
    """
    text = message.get("text", "").strip()
    match = re.match(r"^(query|ask|sor)\s+(.*)", text, re.IGNORECASE)
    
    if not match:
        say(
            "❓ *Nasıl kullanılır:*\n"
            "`query <sorunuz>` veya `ask <sorunuz>`\n\n"
            "*Örnek sorular:*\n"
            "• `query Son 7 günde kaç zararlı domain tespit ettik?`"
        )
        return
        
    user_question = match.group(2).strip()
    
    if not user_question:
        say("❓ Lütfen bir soru yazın. Örnek: `query Son 24 saatte ne analiz edildi?`")
        return
    
    say(f"🤖 Sorunuz işleniyor: _{user_question}_")
    
    try:
        result = nl_query_engine.ask(user_question)
        answer = result.get("answer", "Yanıt alınamadı.")
        row_count = result.get("row_count", 0)
        success = result.get("success", False)
        
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*🤖 SOC Asistanı*\n\n{answer}"
                }
            }
        ]
        
        if success and row_count > 0:
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"📌 _{row_count} kayıt üzerinden analiz yapıldı_"
                    }
                ]
            })
        
        say(blocks=blocks, text=answer)
        
    except Exception as e:
        say(f"❌ Sorgu işlenirken hata oluştu: `{str(e)}`")

# ============================================================================
# ACTION HANDLERS (Buttons)
# ============================================================================

@app.action("download_pdf")
def handle_pdf(ack, body, client):
    ack()
    filepath = body['actions'][0]['value']
    channel = body['channel']['id']
    if os.path.exists(filepath):
        client.files_upload_v2(channel=channel, file=filepath, title="Security Report")
    else:
        client.chat_postMessage(channel=channel, text="⚠️ PDF file not found.")

@app.action("show_graph")
def handle_graph(ack, body, client):
    ack()
    filepath = body['actions'][0]['value']
    channel = body['channel']['id']
    if os.path.exists(filepath):
        client.files_upload_v2(channel=channel, file=filepath, title="XAI Graph")
    else:
        client.chat_postMessage(channel=channel, text="⚠️ Graph file not found.")

# --- MAIN ---

if __name__ == "__main__":
    print("🚀 ChatSecOps Slack Bot (Hybrid v5.0) is starting...")
    SocketModeHandler(app, os.getenv("SLACK_APP_TOKEN")).start()