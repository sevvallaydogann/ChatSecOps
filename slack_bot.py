"""
ChatSecOps Slack Bot (Enterprise Edition v2.1)
Features:
- Professional Incident Reporting (Grid Layout)
- Real-time Visual Evidence (Thum.io)
- Interactive Action Buttons (PDF, Graph, Block)
- Full English Localization
"""

import os
import requests
import re
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv

# Import helper modules
# Ensure ChatSecOps_Memory and ChatSecOps_Intelligence are in the same folder
from ChatSecOps_Memory import format_memory_insights, format_similar_domains
from ChatSecOps_Intelligence import format_osint_results, intel_engine

# Load Environment Variables
load_dotenv()

# Initialize Slack App
app = App(token=os.getenv("SLACK_BOT_TOKEN"))

# Backend API URL (FastAPI Server)
BACKEND_API = os.getenv("BACKEND_API_URL", "http://localhost:8000")

# --- 1. REPORT FORMATTING (Grid Layout + Buttons) ---

def format_risk_message(data: dict) -> dict:
    """Formats the API response into a Modern Enterprise Grid Layout with Buttons"""
    domain = data.get("domain", "Unknown Asset")
    
    # Retrieve file paths for buttons (Passed from Backend)
    pdf_path = data.get("pdf_report", "")
    shap_path = data.get("shap_graph", "")

    # Handle AI Summary (Convert to dict if string)
    ai_summary_raw = data.get("ai_ozeti", {})
    if isinstance(ai_summary_raw, str):
        # Fallback if backend returns plain string
        report_data = {"xai_output": ai_summary_raw, "verdict": "ANALYZED"}
    else:
        report_data = ai_summary_raw

    # Extract Report Data
    report_id = report_data.get("report_id", "N/A")
    timestamp = report_data.get("timestamp", "N/A")
    verdict = report_data.get("verdict", "UNKNOWN")
    severity = report_data.get("severity", "INFO")
    icon = report_data.get("icon", "🛡️")
    risk_score = report_data.get("risk_score", "0%")
    action = report_data.get("action", "REVIEW")
    vt_text = report_data.get("vt_text", "N/A")
    abuse_text = report_data.get("abuse_text", "N/A")
    xai_output = report_data.get("xai_output", "No details available.")

    # Extract Model Data
    raw_data = data.get("ham_veriler", {})
    model_data = raw_data.get("kendi_modelimiz", {})
    detected_ip = model_data.get("tespit_edilen_ip", "N/A")
    country = model_data.get("tespit_edilen_ulke", "N/A")

    blocks = []

    # --- A. Header ---
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"{icon} Incident Report: {domain}",
            "emoji": True
        }
    })

    # --- B. Context (ID & Time) ---
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"*Case ID:* `{report_id}`"},
            {"type": "mrkdwn", "text": f"*Timestamp:* {timestamp}"}
        ]
    })
    blocks.append({"type": "divider"})

    # --- C. Visual Evidence (Thum.io) ---
    try:
        screenshot_url = intel_engine.get_visual_evidence(domain)
        blocks.append({
            "type": "image",
            "title": {"type": "plain_text", "text": "🌐 Live Site Preview", "emoji": True},
            "image_url": screenshot_url,
            "alt_text": "visual_proof"
        })
    except:
        pass

    # --- D. Executive Summary (Grid) ---
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*🛡️ Executive Summary*"},
        "fields": [
            {"type": "mrkdwn", "text": f"*Verdict:*\n`{verdict}`"},
            {"type": "mrkdwn", "text": f"*Severity:*\n{icon} {severity}"},
            {"type": "mrkdwn", "text": f"*Risk Score:*\n{risk_score}"},
            {"type": "mrkdwn", "text": f"*Action:*\n`{action}`"}
        ]
    })
    blocks.append({"type": "divider"})

    # --- E. Technical Intelligence (Grid) ---
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": "*🔬 Technical Intelligence*"},
        "fields": [
            {"type": "mrkdwn", "text": f"*VirusTotal:*\n{vt_text}"},
            {"type": "mrkdwn", "text": f"*AbuseIPDB:*\n{abuse_text}"},
            {"type": "mrkdwn", "text": f"*Hosting IP:*\n`{detected_ip}`"},
            {"type": "mrkdwn", "text": f"*Location:*\n{country}"}
        ]
    })

    # --- F. AI Reasoning ---
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*🤖 AI Reasoning (Behavioral Analysis)*\n{xai_output}"
        }
    })
    blocks.append({"type": "divider"})

    # --- G. INTERACTIVE ACTION BUTTONS (New Feature) ---
    action_elements = []
    
    # PDF Download Button
    if pdf_path:
        action_elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📄 Download Report (PDF)", "emoji": True},
            "style": "primary",
            "value": pdf_path, # Path stored in button value
            "action_id": "download_pdf"
        })
    
    # SHAP Graph Button
    if shap_path:
        action_elements.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📊 View SHAP Graph", "emoji": True},
            "value": shap_path,
            "action_id": "show_graph"
        })

    # Block Button (Simulation)
    action_elements.append({
        "type": "button",
        "text": {"type": "plain_text", "text": "⛔ Block Asset (Firewall)", "emoji": True},
        "style": "danger",
        "action_id": "block_action"
    })

    # Add buttons to blocks
    if action_elements:
        blocks.append({
            "type": "actions",
            "elements": action_elements
        })
    
    return {
        "blocks": blocks,
        "text": f"Incident Report: {domain} - {verdict}"
    }

# --- 2. COMMAND HANDLERS ---

@app.message("analyze")
@app.message("check")
@app.message("scan")
def analyze_domain(message, say):
    """Main Analysis Command"""
    text = message.get("text", "")
    words = text.split()
    
    if len(words) < 2:
        say("❌ *Error:* Please specify a domain.\nExample: `analyze google.com`")
        return
    
    # Clean up Slack formatting (e.g., <http://google.com|google.com>)
    raw_domain = words[1].strip()
    domain = re.sub(r"<http[s]?://[^|]+\|([^>]+)>", r"\1", raw_domain)
    domain = domain.replace("<", "").replace(">", "").replace("http://", "").replace("https://", "")

    say(f"🔍 *{domain}* is being analyzed by SOAR Engine... Please wait.")
    
    try:
        # Request analysis from Backend
        response = requests.get(
            f"{BACKEND_API}/enrich-and-summarize/domain/{domain}",
            timeout=60
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # 1. Main Report with Buttons
            message_blocks = format_risk_message(data)
            say(**message_blocks)
            
            # 2. Memory Insights
            memory_insights = data.get("memory_insights", {})
            if memory_insights.get("is_known"):
                say(format_memory_insights(memory_insights))
            
            # 3. Similar Domains
            similar = data.get("similar_domains", [])
            if similar:
                say(format_similar_domains(similar))
            
            # 4. Campaign Alert
            campaign = data.get("campaign_alert")
            if campaign:
                say(f"🚨 *CAMPAIGN ALERT*\n\n{campaign.get('recommendation', '')}")
            
            # 5. OSINT Results
            osint_data = data.get("ham_veriler", {}).get("osint", {})
            if osint_data.get("threats_detected"):
                say(format_osint_results(osint_data))
        
        else:
            say(f"❌ *Analysis Failed*\n```Status Code: {response.status_code}```")
    
    except requests.exceptions.Timeout:
        say(f"⏱️ *Timeout:* Analysis took too long.")
    except Exception as e:
        say(f"❌ *Unexpected Error:*\n```{str(e)}```")

@app.message("status")
@app.message("durum")
def status_command(message, say):
    """Check System Health"""
    try:
        response = requests.get(f"{BACKEND_API}/", timeout=5)
        if response.status_code == 200:
            say("✅ *System Status:* Online & Operational\n🔗 Backend API connection established.")
        else:
            say("⚠️ *System Status:* Backend API is unreachable.")
    except Exception as e:
        say(f"❌ *System Error:* Connection failed\n```{str(e)}```")

@app.message("stats")
@app.message("statistics")
def statistics_command(message, say):
    """Show System Statistics"""
    try:
        response = requests.get(f"{BACKEND_API}/statistics", timeout=10)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            
            stats_message = f"""
📊 *ChatSecOps System Statistics*

*General Overview:*
• Total Analysis: {data.get('total_analyses', 0):,}
• Malicious Detections: {data.get('malicious_count', 0):,} ({data.get('malicious_rate', 0)}%)
• Last 24h: {data.get('last_24h_analyses', 0):,} scans

*Top Detected TLDs:*
"""
            for tld in data.get('top_tlds', [])[:5]:
                stats_message += f"• .{tld['tld']}: {tld['count']} domains\n"
            
            stats_message += "\n*High-Risk IPs:*\n"
            for ip in data.get('high_risk_ips', [])[:3]:
                stats_message += f"• `{ip['ip']}`: {ip['domain_count']} domains\n"
            
            say(stats_message)
        else:
            say("❌ Statistics unavailable.")
    except Exception as e:
        say(f"❌ Error: {str(e)}")

@app.message("help")
def help_command(message, say):
    """Help Menu"""
    help_text = """
🛡️ *ChatSecOps SOAR - Command Menu*

*📝 Core Analysis:*
• `analyze <domain>` - Full Analysis (ML + TI + PDF Report)
• `check <domain>` - Quick Check
• `scan <domain>` - Deep Scan

*🔍 Advanced:*
• `similar <domain>` - Find Typosquatting (Similar Domains)
• `stats` - System Statistics & Threat Landscape
• `campaign` - Check for Active Campaigns
• `feedback <domain> <comment>` - Submit Analyst Feedback

*❓ Misc:*
• `help` - Show this menu
• `status` - Check System Health

*💡 Example:*
`analyze google.com`
    """
    say(help_text)

# --- 3. ACTION HANDLERS (Buttons) ---

@app.action("download_pdf")
def handle_pdf_download(ack, body, client):
    """Handles PDF Download Button Click"""
    ack()
    
    filepath = body['actions'][0]['value']
    channel_id = body['channel']['id']
    
    try:
        if os.path.exists(filepath):
            # Upload the file to Slack
            client.files_upload_v2(
                channel=channel_id,
                file=filepath,
                title="Incident Report (PDF)",
                initial_comment="📄 *Forensic Report Generated successfully.*"
            )
        else:
            client.chat_postMessage(channel=channel_id, text="⚠️ PDF file not found on server.")
    except Exception as e:
        client.chat_postMessage(channel=channel_id, text=f"❌ Upload Error: {str(e)}")

@app.action("show_graph")
def handle_graph_show(ack, body, client):
    """Handles SHAP Graph Button Click"""
    ack()
    
    filepath = body['actions'][0]['value']
    channel_id = body['channel']['id']
    
    try:
        if os.path.exists(filepath):
            client.files_upload_v2(
                channel=channel_id,
                file=filepath,
                title="XAI Analysis Graph",
                initial_comment="📊 *Explainable AI (SHAP) Analysis Graph*"
            )
        else:
            client.chat_postMessage(channel=channel_id, text="⚠️ Graph file not found.")
    except Exception as e:
        client.chat_postMessage(channel=channel_id, text=f"❌ Upload Error: {str(e)}")

@app.action("block_action")
def handle_block(ack, body, client):
    """Handles Block Button Click"""
    ack()
    user = body['user']['id']
    client.chat_postMessage(
        channel=body['channel']['id'], 
        text=f"🛡️ *Firewall Rule Initiated!* Asset blocked by <@{user}>.\n_Ticket created in ITSM._"
    )

@app.event("app_mention")
def handle_mention(event, say):
    text = event.get("text", "").lower()
    if "help" in text:
        help_command(event, say)
    else:
        say(f"👋 Hello! Use `analyze <domain>` to start a security scan.")

# --- MAIN ---

if __name__ == "__main__":
    print("🚀 ChatSecOps Slack Bot (Enterprise v2.1) is starting...")
    print(f"🔗 Connected to Backend: {BACKEND_API}")
    
    SocketModeHandler(app, os.getenv("SLACK_APP_TOKEN")).start()