"""
slack_bot.py - HYBRID VERSION v6.0
Integrates the AI Agent (Feature 6) as the primary analysis path.
Falls back to direct API calls for non-agent flows.

Feature 1: Full URL analysis (path, query, defanged URLs)
Feature 2: Pivot chain notifications
Feature 4: Natural language query interface
Feature 6: AI Agent (Gemini ReAct / Groq / local fallback)
"""

import os
import re
import requests
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from dotenv import load_dotenv

from ChatSecOps_NLQuery import nl_query_engine
from ChatSecOps_MITRE import mitre_mapper
from ChatSecOps_Agent import investigate as agent_investigate

# Bootstrap
load_dotenv()

app = App(token=os.getenv("SLACK_BOT_TOKEN"))
BACKEND_API = os.getenv("BACKEND_API_URL", "http://localhost:8000")


# HELPER: MESSAGE FORMATTER
# Converts the raw API JSON into Slack Block Kit cards.


def format_risk_message(data: dict) -> dict:
    domain      = data.get("domain", "Unknown")
    is_url_scan = bool(data.get("url_analysis"))  # True when full URL was scanned

    # --- AI Summary ---
    ai_raw = data.get("ai_ozeti", {})
    if isinstance(ai_raw, dict):
        ai_text = ai_raw.get("xai_output", "Analysis unavailable.")
    else:
        ai_text = str(ai_raw)

    # --- Raw data ---
    raw        = data.get("ham_veriler", {})
    model_data = raw.get("kendi_modelimiz", {})
    vt_data    = raw.get("virustotal", {})
    abuse_data = raw.get("abuseipdb", {})
    osint_data = raw.get("osint", {})

    ml_risk     = model_data.get("risk_skoru_yuzde", "0%")
    detected_ip = model_data.get("tespit_edilen_ip", "N/A")
    country     = model_data.get("tespit_edilen_ulke", "Unknown")

    # --- Determine display score & verdict ---
    if is_url_scan and data.get("combined_score"):
        display_score = data["combined_score"]
        score_label   = "Combined Risk Score"
    else:
        display_score = ml_risk
        score_label   = "ML Risk Score"

    # --- Risk colour & emoji (verdict always derived from score) ---
    try:
        risk_num = float(str(display_score).replace("%", ""))
    except Exception:
        risk_num = 0.0

    if risk_num >= 80:
        emoji, color    = "🔴", "#d73a49"
        display_verdict = "CRITICAL"
    elif risk_num >= 50:
        emoji, color    = "🟠", "#fb8500"
        display_verdict = "HIGH"
    elif risk_num >= 20:
        emoji, color    = "🟡", "#ffb700"
        display_verdict = "MEDIUM"
    else:
        emoji, color    = "🟢", "#28a745"
        display_verdict = "SAFE"

    # Allow backend to override verdict label if explicitly set
    display_verdict = data.get("combined_verdict") or display_verdict

    # --- Intel feed statuses ---
    if "hata" not in vt_data and vt_data:
        vt_mal    = vt_data.get("malicious", 0)
        vt_total  = sum(vt_data.values())
        vt_icon   = "🔴" if vt_mal > 0 else "✅"
        vt_status = f"{vt_icon} {vt_mal}/{vt_total} flagged"
    else:
        vt_status = "⚪ Data Unavailable"

    av = osint_data.get("alienvault", {})
    if av and not av.get("error"):
        av_count  = av.get("pulse_count", 0)
        av_icon   = "🔴" if av_count > 0 else "✅"
        av_status = f"{av_icon} {av_count} Pulses"
    else:
        av_status = "⚪ N/A"

    sho = osint_data.get("shodan", {})
    if sho and not sho.get("error"):
        ports      = len(sho.get("ports", []))
        vulns      = len(sho.get("vulns", []))
        sho_icon   = "⚠️" if vulns > 0 else "ℹ️"
        sho_status = f"{sho_icon} Ports: {ports} | Vulns: {vulns}"
    else:
        sho_status = "⚪ No IP Resolved" if (not detected_ip or detected_ip == "N/A") else "⚪ Not Found"

    # --- Header: distinguish URL scan vs domain scan ---
    if is_url_scan:
        url_analysis  = data.get("url_analysis", {})
        original_url  = url_analysis.get("original_url", domain)
        header_text   = f"{emoji} URL Security Report: {original_url}"
        # Show both scores so there is no confusion
        ml_score_note = f"*Domain ML Score:*\n{ml_risk} _(domain only)_"
        combined_note = f"*{score_label}:*\n{display_score} _(URL + domain)_"
        score_fields  = [
            {"type": "mrkdwn", "text": f"*Verdict:*\n{display_verdict}"},
            {"type": "mrkdwn", "text": f"*{score_label}:*\n{display_score}"},
            {"type": "mrkdwn", "text": ml_score_note},
            {"type": "mrkdwn", "text": f"*IP Address:*\n`{detected_ip}` ({country})"},
        ]
    else:
        header_text  = f"{emoji} Domain Security Report: {domain}"
        score_fields = [
            {"type": "mrkdwn", "text": f"*Verdict:*\n{display_verdict}"},
            {"type": "mrkdwn", "text": f"*{score_label}:*\n{display_score}"},
            {"type": "mrkdwn", "text": f"*IP Address:*\n`{detected_ip}`"},
            {"type": "mrkdwn", "text": f"*Location:*\n{country}"},
        ]

    # --- Build blocks ---
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": header_text, "emoji": True}
        },
        {
            "type": "section",
            "fields": score_fields
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*🔬 Threat Intelligence Feeds*"},
            "fields": [
                {"type": "mrkdwn", "text": f"*VirusTotal:*\n{vt_status}"},
                {"type": "mrkdwn", "text": f"*AbuseIPDB:*\nScore: {abuse_data.get('abuseConfidenceScore', 'N/A')}%"},
                {"type": "mrkdwn", "text": f"*AlienVault OTX:*\n{av_status}"},
                {"type": "mrkdwn", "text": f"*Shodan:*\n{sho_status}"},
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*🤖 AI Analysis Summary*\n{ai_text}"}
        },
    ]

    # Optional: live site screenshot — validate before adding to blocks
    try:
        import requests as _req
        img_url = f"https://image.thum.io/get/width/600/crop/800/noanimate/http://{domain}"
        r = _req.head(img_url, timeout=5, allow_redirects=True)
        content_type = r.headers.get("Content-Type", "")
        if r.status_code == 200 and "image" in content_type:
            blocks.append({
                "type": "image",
                "image_url": img_url,
                "alt_text": "site_preview",
                "title": {"type": "plain_text", "text": "🌍 Live Site Preview"}
            })
    except Exception:
        pass

    # Action buttons
    actions = []
    if data.get("pdf_report"):
        actions.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📄 Download PDF"},
            "value": data["pdf_report"],
            "action_id": "download_pdf",
        })
    if data.get("shap_graph"):
        actions.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "📊 Technical Graph"},
            "value": data["shap_graph"],
            "action_id": "show_graph",
        })
    if actions:
        blocks.append({"type": "actions", "elements": actions})

    return {
        "text": f"Report for {domain}: {display_verdict}",
        "blocks": blocks,
        "attachments": [{"color": color, "blocks": []}],
    }



# COMMAND HANDLERS


@app.message(re.compile(r"^help$", re.IGNORECASE))
def help_command(message, say):
    say("""
🛡️ *ChatSecOps SOAR — Command Menu*

*🔍 Analysis Commands:*
• `analyze <domain>` — Full security scan (VT, Shodan, OTX, AI Agent)
• `analyze <full_url>` — URL analysis (path, query, redirect detection)
• `check <domain>` — Quick check
• `scan <domain>` — Deep scan

*🤖 AI Agent (Feature 6):*
The agent automatically decides which tools to run (VirusTotal, AlienVault,
Shodan, Pivot, MITRE ATT&CK) and synthesises a full English report.

*💬 Natural Language Query (Feature 4):*
• `query <question>` — Query the threat database in plain English
• `ask <question>` — Same (English alias)

*Example queries:*
• `query How many malicious domains in the last 7 days?`
• `query Top 5 riskiest domains?`
• `query Which countries are threats coming from?`
• `query Which TLDs are most malicious?`

*📊 System:*
• `stats` — Threat statistics
• `status` — API health check

*💡 Examples:*
`analyze google.com`
`analyze hxxps://paypal-security.tk/login?redirect=paypal.com`
""")


@app.message(re.compile(r"^status$", re.IGNORECASE))
def status_command(message, say):
    try:
        r = requests.get(f"{BACKEND_API}/", timeout=5)
        if r.status_code == 200:
            say("✅ *System Status:* Online & Operational\n🔗 Backend API connected.")
        else:
            say("⚠️ *System Status:* Backend API reachable but returned error.")
    except Exception as e:
        say(f"❌ *System Status:* Connection Failed\n```{str(e)}```")


@app.message(re.compile(r"^stats$", re.IGNORECASE))
def statistics_command(message, say):
    try:
        r = requests.get(f"{BACKEND_API}/statistics", timeout=10)
        if r.status_code == 200:
            data = r.json().get("data", {})
            say(
                f"📊 *System Statistics*\n"
                f"• Total Scans: {data.get('total_analyses', 0)}\n"
                f"• Malicious: {data.get('malicious_count', 0)}"
            )
        else:
            say("❌ Stats unavailable.")
    except Exception:
        say("❌ Stats error.")



# ANALYZE — Feature 1 + Feature 6 (AI Agent)


@app.message(re.compile(r"^(analyze|check|scan)\s+(.*)", re.IGNORECASE))
def analyze_domain(message, say):
    text  = message.get("text", "").strip()
    match = re.match(r"^(analyze|check|scan)\s+(.*)", text, re.IGNORECASE)

    if not match:
        say("❌ *Error:* Please specify a domain or URL.\nExample: `analyze evil.tk`")
        return

    # Clean the raw input
    raw_input = match.group(2).strip()
    # Slack auto-formats URLs as <https://example.com|example.com> — unwrap
    raw_input = re.sub(r"<https?://[^|>]+\|([^>]+)>", r"\1", raw_input)
    raw_input = re.sub(r"<https?://([^>]+)>", r"\1", raw_input)
    raw_input = raw_input.replace("<", "").replace(">", "").strip()

    # Determine target for the agent
    # Defanged URL normalisation (hxxps → https, [.] → .)
    normalised = raw_input.lower().replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")

    is_full_url = (
        normalised.startswith("http://")
        or normalised.startswith("https://")
        or "/" in raw_input
        or "?" in raw_input
        or "=" in raw_input
        or raw_input.lower().startswith("hxxp")
    )

    agent_target = normalised if is_full_url else raw_input

    # Step 1: AI Agent 
    say(f"🤖 *ChatSecOps AI Agent* is investigating `{raw_input}`...\n_Selecting tools and building evidence chain..._")

    try:
        agent_response = agent_investigate(agent_target)
        say(agent_response)
    except Exception as e:
        say(f"⚠️ *Agent error:* `{str(e)}`\nFalling back to standard pipeline...")

    # Step 2: Standard pipeline (ML model + PDF + MITRE + Pivot blocks)
    # The agent gives the AI narrative; the standard API gives structured blocks
    # (risk card, PDF button, SHAP graph, pivot alert, MITRE blocks).
    if is_full_url:
        try:
            api_response = requests.get(
                f"{BACKEND_API}/analyze-url",
                params={"url": raw_input},
                timeout=90,
            )
        except requests.exceptions.Timeout:
            say("⏱️ *Timeout:* URL analysis took too long.")
            return
        except Exception as e:
            say(f"❌ *Pipeline error:* {str(e)}")
            return
    else:
        domain = raw_input.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            api_response = requests.get(
                f"{BACKEND_API}/enrich-and-summarize/domain/{domain}",
                timeout=90,
            )
        except requests.exceptions.Timeout:
            say("⏱️ *Timeout:* Analysis took too long.")
            return
        except Exception as e:
            say(f"❌ *Pipeline error:* {str(e)}")
            return

    if api_response.status_code != 200:
        say(f"❌ *Pipeline failed* (HTTP {api_response.status_code})")
        return

    data = api_response.json()

    # Structured risk card
    say(**format_risk_message(data))

    # URL structural findings — only show if there are meaningful findings
    # Scores are already shown in the main risk card above, so we skip them here
    url_analysis = data.get("url_analysis")
    if url_analysis and url_analysis.get("findings"):
        url_risk_level = url_analysis.get("url_risk_level", "LOW")
        if url_risk_level in ("HIGH", "CRITICAL", "MEDIUM"):  # skip LOW-only findings
            findings_text = "\n".join(f"  • {f}" for f in url_analysis["findings"][:5])
            say(
                f"🔗 *URL Structural Findings*\n"
                f"*URL Risk Level:* {url_risk_level}\n"
                f"*Indicators:*\n{findings_text}"
            )

    # Pivot chain notification
    pivot = data.get("pivot_chain", {})
    if pivot.get("triggered") and pivot.get("total_related", 0) > 0:
        say(
            f"🕸️ *Pivot Chain Alert:* {pivot['total_related']} co-hosted domain(s) "
            f"found on the same IP. "
            f"{pivot.get('auto_analyzed_count', 0)} domain(s) auto-analysed."
        )

    # MITRE ATT&CK blocks
    mitre_result = data.get("mitre_attack", {})
    if mitre_result and mitre_result.get("total_triggered", 0) > 0:
        mitre_blocks = mitre_mapper.format_for_slack_block(mitre_result)
        if mitre_blocks:
            say(blocks=mitre_blocks, text="MITRE ATT&CK Techniques Identified")

    # Memory insight
    mem = data.get("memory_insights", {})
    if mem.get("is_known"):
        say(f"🧠 *Memory:* This domain was analysed {mem['analysis_count']} time(s) before.")



# NATURAL LANGUAGE QUERY 


@app.message(re.compile(r"^(query|ask|sor)\s+(.*)", re.IGNORECASE))
def handle_nl_query(message, say):
    text  = message.get("text", "").strip()
    match = re.match(r"^(query|ask|sor)\s+(.*)", text, re.IGNORECASE)

    if not match:
        say(
            "❓ *Usage:* `query <your question>` or `ask <your question>`\n\n"
            "*Examples:*\n"
            "• `query How many malicious domains in the last 7 days?`\n"
            "• `ask Top 5 riskiest domains?`"
        )
        return

    user_question = match.group(2).strip()
    if not user_question:
        say("❓ Please write a question. Example: `query What was analysed in the last 24 hours?`")
        return

    say(f"🤖 Processing your query: _{user_question}_")

    try:
        result    = nl_query_engine.ask(user_question)
        answer    = result.get("answer", "No answer returned.")
        row_count = result.get("row_count", 0)
        success   = result.get("success", False)

        blocks = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🤖 SOC Assistant*\n\n{answer}"}
            }
        ]
        if success and row_count > 0:
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"📌 _{row_count} record(s) analysed_"}]
            })

        say(blocks=blocks, text=answer)

    except Exception as e:
        say(f"❌ Query error: `{str(e)}`")



# ACTION HANDLERS (Buttons)


@app.action("download_pdf")
def handle_pdf(ack, body, client):
    ack()
    filepath = body["actions"][0]["value"]
    channel  = body["channel"]["id"]
    if os.path.exists(filepath):
        client.files_upload_v2(channel=channel, file=filepath, title="Security Report")
    else:
        client.chat_postMessage(channel=channel, text="⚠️ PDF file not found on server.")


@app.action("show_graph")
def handle_graph(ack, body, client):
    ack()
    filepath = body["actions"][0]["value"]
    channel  = body["channel"]["id"]
    if os.path.exists(filepath):
        client.files_upload_v2(channel=channel, file=filepath, title="XAI Explanation Graph")
    else:
        client.chat_postMessage(channel=channel, text="⚠️ Graph file not found on server.")



# MAIN


if __name__ == "__main__":
    print("🚀 ChatSecOps Slack Bot (Hybrid v6.0) is starting...")
    SocketModeHandler(app, os.getenv("SLACK_APP_TOKEN")).start()