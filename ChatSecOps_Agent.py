"""
ChatSecOps_Agent.py  —  AI Agent 
=============================================
Architecture: ReAct loop via Gemini Function Calling.
Fallback chain: Gemini 2.0 Flash → Groq Llama-3 → Local rule-based engine.

The agent receives a domain/URL, decides which tools to call (VirusTotal,
Shodan, AlienVault, Pivot, MITRE, Memory, PDF), executes them, observes
the results, and synthesises a final English answer for Slack.
"""

import os
import json
import time
import logging
import requests
from typing import Any

from google import genai
from google.genai import types as genai_types

# Local modules 
from ChatSecOps_Intelligence import intel_engine
from ChatSecOps_URLParser import url_parser
from ChatSecOps_MITRE import mitre_mapper
from ChatSecOps_Pivot import pivot_engine
from ChatSecOps_Memory import ThreatMemoryEngine
from ChatSecOps_Analytics import create_pdf_report

logger = logging.getLogger(__name__)

# Singletons 
memory_engine = ThreatMemoryEngine()

# 1.  TOOL IMPLEMENTATIONS
#     Each function is called by the agent when it decides to use that tool.

def tool_check_virustotal(domain: str) -> dict:
    """Query VirusTotal for malicious/suspicious vote counts."""
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return {"error": "VIRUSTOTAL_API_KEY not set"}
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": vt_key}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "source": "VirusTotal"
            }
        return {"error": f"VT HTTP {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def tool_check_alienvault(domain: str) -> dict:
    """Query AlienVault OTX for threat pulses."""
    result = intel_engine.check_alienvault(domain)
    return result if result else {"found": False}


def tool_check_shodan(ip_address: str) -> dict:
    """Query Shodan for open ports and banners on an IP."""
    result = intel_engine.check_shodan(ip_address)
    return result if result else {"error": "No data"}


def tool_run_pivot(domain: str, ip_address: str, risk_score: float = 50.0) -> dict:
    """
    Run IOC pivot chain: find co-hosted domains on the same IP
    via the DB and Shodan, then flag any malicious neighbours.
    Calls pivot_engine.run_pivot(trigger_domain, ip_address, trigger_risk_score).
    """
    try:
        result = pivot_engine.run_pivot(
            trigger_domain=domain,
            ip_address=ip_address,
            trigger_risk_score=float(risk_score),
        )
        return result if result else {"pivot_found": False}
    except Exception as e:
        return {"error": str(e)}


def tool_map_mitre(analysis_result: str) -> dict:
    """
    Map analysis JSON string to MITRE ATT&CK techniques.
    Pass the full analysis result as a JSON string.
    """
    try:
        data = json.loads(analysis_result)
        result = mitre_mapper.map(data)
        return result if result else {"techniques": []}
    except Exception as e:
        return {"error": str(e)}


def tool_get_memory(domain: str) -> dict:
    """Retrieve previous analysis history for this domain from the DB."""
    try:
        insights = memory_engine.get_domain_insights(domain)
        return insights if insights else {"history": "First time seen"}
    except Exception as e:
        return {"error": str(e)}


def tool_parse_url(url: str) -> dict:
    """
    Parse and enrich a raw/defanged URL: normalise, score path/query
    risk, and extract host.
    Calls url_parser.analyze(raw_url) which returns url_risk_boost, findings, risk_level.
    """
    try:
        result = url_parser.analyze(url)
        return result if result else {"error": "Parse failed"}
    except Exception as e:
        return {"error": str(e)}


def tool_generate_pdf(
    domain: str,
    ai_summary: str,
    risk_score: float,
    vt_stats: str,
) -> dict:
    """
    Generate a PDF threat intelligence report and return the file path.
    vt_stats must be a JSON string of VirusTotal stats dict.
    """
    try:
        vt = json.loads(vt_stats) if isinstance(vt_stats, str) else vt_stats
        path = create_pdf_report(
            domain=domain,
            ai_summary=ai_summary,
            risk_score=float(risk_score),
            vt_stats=vt,
        )
        return {"pdf_path": path, "success": True}
    except Exception as e:
        return {"error": str(e), "success": False}


# 2.  TOOL REGISTRY
#     Maps Gemini FunctionDeclaration names → Python callables.

TOOL_CALLABLES = {
    "check_virustotal": tool_check_virustotal,
    "check_alienvault": tool_check_alienvault,
    "check_shodan":     tool_check_shodan,
    "run_pivot":        tool_run_pivot,   # (domain, ip_address, risk_score=50.0)
    "map_mitre":        tool_map_mitre,
    "get_memory":       tool_get_memory,
    "parse_url":        tool_parse_url,
    "generate_pdf":     tool_generate_pdf,
}

# Gemini Function Declarations — new google.genai SDK format
def _make_str_param(description: str):
    return genai_types.Schema(type="STRING", description=description)

def _make_num_param(description: str):
    return genai_types.Schema(type="NUMBER", description=description)

GEMINI_TOOLS = genai_types.Tool(function_declarations=[
    genai_types.FunctionDeclaration(
        name="check_virustotal",
        description="Query VirusTotal to get malicious/suspicious/harmless vote counts for a domain.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={"domain": _make_str_param("Domain name, e.g. evil.tk")},
            required=["domain"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="check_alienvault",
        description="Query AlienVault OTX for threat intelligence pulses associated with a domain.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={"domain": _make_str_param("Domain name to look up")},
            required=["domain"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="check_shodan",
        description="Query Shodan for open ports, services, and banners on an IP address.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={"ip_address": _make_str_param("IPv4 address")},
            required=["ip_address"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="run_pivot",
        description="Run IOC pivot chain: find co-hosted domains on the same IP and flag malicious neighbours.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={
                "domain":     _make_str_param("Target domain"),
                "ip_address": _make_str_param("Resolved IP of the target domain"),
                "risk_score": _make_num_param("Risk score of the trigger domain 0-100, default 50"),
            },
            required=["domain", "ip_address"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="map_mitre",
        description="Map analysis findings to MITRE ATT&CK techniques. Pass the full analysis as a JSON string.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={"analysis_result": _make_str_param("Full analysis result serialised as JSON")},
            required=["analysis_result"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="get_memory",
        description="Retrieve previous analysis history and threat memory for a domain from the local database.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={"domain": _make_str_param("Domain name")},
            required=["domain"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="parse_url",
        description="Parse and score a raw or defanged URL: normalise it, score path/query risk, extract host.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={"url": _make_str_param("Raw or defanged URL to parse")},
            required=["url"],
        ),
    ),
    genai_types.FunctionDeclaration(
        name="generate_pdf",
        description="Generate a PDF threat intelligence report. Call this only after collecting all evidence.",
        parameters=genai_types.Schema(
            type="OBJECT",
            properties={
                "domain":     _make_str_param("Target domain"),
                "ai_summary": _make_str_param("Final analysis summary text"),
                "risk_score": _make_num_param("Risk score 0-100"),
                "vt_stats":   _make_str_param("VirusTotal stats serialised as JSON string"),
            },
            required=["domain", "ai_summary", "risk_score", "vt_stats"],
        ),
    ),
])


# 3.  SYSTEM PROMPT

SYSTEM_PROMPT = """
You are the ChatSecOps Autonomous Cyber Security Threat Intelligence Agent.

Your mission: investigate any domain or URL sent by a SOC analyst via Slack.
Follow this ReAct strategy:

THINK  → what do I know so far? what do I still need?
ACT    → call the most relevant tool
OBSERVE → read the tool result carefully
REPEAT → until you have enough evidence to give a verdict

Investigation order (adapt based on findings):
1. parse_url  — always start here if a full URL is given
2. get_memory — check if we have prior history
3. check_virustotal — core reputation check
4. check_alienvault — threat intelligence pulses
5. check_shodan  — only if VT or OTX shows risk > 30 or unknown
6. run_pivot — only if risk > 50 or suspicious infrastructure detected
7. map_mitre — only if any tool returned a threat finding
8. generate_pdf — always call at the end to produce the report

Rules:
- Skip tools that are clearly unnecessary (e.g. do NOT run pivot on a well-known safe domain).
- Never call the same tool twice with the same arguments.
- All output must be in English.
- Final answer format (Slack markdown):

*🔍 ChatSecOps Agent — Investigation Complete*

*Target:* `<domain>`
*Verdict:* SAFE | LOW | MEDIUM | HIGH | CRITICAL
*Risk Score:* X/100

*📊 Evidence Summary*
• VirusTotal: ...
• AlienVault: ...
• Shodan: ...
• Pivot: ...
• MITRE ATT&CK: ...

*🧠 Analysis*
<2–3 sentence synthesis of all findings>

*✅ Recommended Actions*
• ...

*📄 PDF Report:* `<path or 'not generated'>`
""".strip()


# 4.  GEMINI AGENT  (Function Calling ReAct loop)

def run_gemini_agent(target: str, max_turns: int = 10) -> str:
    """
    Run the full ReAct loop with Gemini Function Calling (new google.genai SDK).
    Returns the final text answer.
    """
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
    if not gemini_key or len(gemini_key) < 10:
        raise ValueError(f"GEMINI_API_KEY missing or too short (got: '{gemini_key[:15]}')")

    client = genai.Client(api_key=gemini_key)

    # Build initial message history
    contents = [
        genai_types.Content(
            role="user",
            parts=[genai_types.Part(text=f"Investigate this target: {target}")]
        )
    ]

    config = genai_types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=[GEMINI_TOOLS],
    )

    logger.info(f"[AGENT] Starting Gemini ReAct loop for: {target}")

    for turn in range(max_turns):
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=contents,
            config=config,
        )

        # Collect function calls from this response
        fn_calls = []
        for part in response.candidates[0].content.parts:
            if part.function_call and part.function_call.name:
                fn_calls.append(part.function_call)

        if not fn_calls:
            # No tool calls → done, return text
            text = response.text or ""
            logger.info(f"[AGENT] ReAct loop finished after {turn} tool turns.")
            return text.strip() if text.strip() else "Agent produced no text response."

        # Add model response to history
        contents.append(response.candidates[0].content)

        # Execute tools and build function response parts
        fn_response_parts = []
        for fn_call in fn_calls:
            tool_name = fn_call.name
            tool_args = dict(fn_call.args)
            logger.info(f"[AGENT] Tool call → {tool_name}({tool_args})")

            if tool_name in TOOL_CALLABLES:
                try:
                    result = TOOL_CALLABLES[tool_name](**tool_args)
                except Exception as e:
                    result = {"error": str(e)}
            else:
                result = {"error": f"Unknown tool: {tool_name}"}

            logger.info(f"[AGENT] Tool result ← {tool_name}: {str(result)[:120]}")
            fn_response_parts.append(
                genai_types.Part(
                    function_response=genai_types.FunctionResponse(
                        name=tool_name,
                        response={"result": result},
                    )
                )
            )

        # Add tool results to history as user turn
        contents.append(
            genai_types.Content(role="user", parts=fn_response_parts)
        )

    logger.warning("[AGENT] Max turns reached — returning best available text.")
    try:
        return response.text.strip() or "Agent reached max turns without a final answer."
    except Exception:
        return "Agent reached max turns without a final answer."


# 5.  GROQ FALLBACK  (simple ReAct via text, no native function calling)

def run_groq_fallback(target: str) -> str:
    """
    Groq does not support native function calling in the same way,
    so we pre-run the core tools and pass structured results to Llama-3
    for synthesis.
    """
    groq_key = os.getenv("GROQ_API_KEY", "").strip().strip('"').strip("'")
    if not groq_key or len(groq_key) < 10:
        raise ValueError(f"GROQ_API_KEY missing (got: '{groq_key[:10]}')")

    logger.info(f"[AGENT] Groq fallback starting — key prefix: {groq_key[:8]}... target: {target}")

    # Pre-run the essential tools
    evidence = {}
    try:
        evidence["url_parse"]    = tool_parse_url(target)
    except Exception:
        pass
    try:
        evidence["memory"]       = tool_get_memory(target.split("/")[0])
    except Exception:
        pass
    try:
        evidence["virustotal"]   = tool_check_virustotal(target.split("/")[0])
    except Exception:
        pass
    try:
        evidence["alienvault"]   = tool_check_alienvault(target.split("/")[0])
    except Exception:
        pass

    evidence_text = json.dumps(evidence, indent=2, default=str)

    prompt = f"""{SYSTEM_PROMPT}

Pre-collected tool evidence (JSON):
{evidence_text}

Now write the final Slack investigation report for target: {target}
"""

    headers = {
        "Authorization": f"Bearer {groq_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }
    r = requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=20,
    )
    if r.status_code == 200:
        logger.info("[AGENT] Groq responded successfully.")
        return r.json()["choices"][0]["message"]["content"]
    logger.error(f"[AGENT] Groq failed — HTTP {r.status_code}: {r.text[:300]}")
    raise RuntimeError(f"Groq HTTP {r.status_code}: {r.text[:200]}")


# 6.  LOCAL FALLBACK  (zero-LLM rule-based report)

def run_local_fallback(target: str) -> str:
    """Rule-based fallback when all LLM providers are unavailable."""
    logger.warning("[AGENT] All LLM providers exhausted — running local fallback.")
    domain = target.split("/")[2] if "://" in target else target.split("/")[0]

    vt    = tool_check_virustotal(domain)
    av    = tool_check_alienvault(domain)
    mem   = tool_get_memory(domain)

    mal   = vt.get("malicious", 0)
    sus   = vt.get("suspicious", 0)
    score = min(100, mal * 10 + sus * 5)

    if score > 60:
        verdict = "HIGH"
    elif score > 30:
        verdict = "MEDIUM"
    else:
        verdict = "SAFE"

    lines = [
        "*🔍 ChatSecOps Agent — Investigation Complete* _(Local Fallback Mode)_",
        "",
        f"*Target:* `{domain}`",
        f"*Verdict:* {verdict}",
        f"*Risk Score:* {score}/100",
        "",
        "*📊 Evidence Summary*",
        f"• VirusTotal: {mal} malicious, {sus} suspicious",
        f"• AlienVault: {av.get('pulses', 'N/A')} pulses",
        f"• Memory: {'Seen before' if mem.get('analysis_count', 0) > 0 else 'First time seen'}",
        "",
        "*⚠️ Note:* AI providers (Gemini, Groq) are currently unavailable.",
        "Manual review recommended for definitive verdict.",
    ]
    return "\n".join(lines)



# 7.  PUBLIC ENTRY POINT

def _validate_keys() -> dict:
    """
    Check which API keys are present and valid-looking.
    Gemini keys: old format 'AIzaSy...', new 2025 format 'AQ....'.
    Groq keys: start with 'gsk_'.
    """
    gemini = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
    groq   = os.getenv("GROQ_API_KEY",   "").strip().strip('"').strip("'")

    # Accept both old AIzaSy format and new AQ. format
    gemini_ok = len(gemini) > 10 and (
        gemini.startswith("AIzaSy") or
        gemini.startswith("AQ.")   or
        gemini.startswith("AQ")
    )
    # Just check non-empty with reasonable length
    groq_ok = len(groq) > 10

    return {
        "gemini_ok":  gemini_ok,
        "groq_ok":    groq_ok,
        "gemini_key": gemini[:15] + "..." if gemini else "(empty)",
        "groq_key":   groq[:15]   + "..." if groq   else "(empty)",
    }


def investigate(target: str) -> str:
    """
    Main entry point called by Slack bot and FastAPI.

    Priority chain:
      1. Gemini 2.0 Flash (Function Calling ReAct)
      2. Groq Llama-3 (pre-run tools + synthesis)
      3. Local rule-based fallback
    """
    start    = time.time()
    provider = "unknown"

    keys = _validate_keys()
    logger.info(
        f"[AGENT] Key status — Gemini: {'✅' if keys['gemini_ok'] else '❌'} ({keys['gemini_key']}) | "
        f"Groq: {'✅' if keys['groq_ok'] else '❌'} ({keys['groq_key']})"
    )

    try:
        if not keys["gemini_ok"]:
            raise ValueError(
                f"GEMINI_API_KEY missing or malformed (got: {keys['gemini_key']}). "
                "Check .env — no quotes, single line, full key."
            )
        result   = run_gemini_agent(target)
        provider = "gemini-2.0-flash"
    except Exception as e:
        logger.warning(f"[AGENT] Gemini failed: {e}")
        try:
            if not keys["groq_ok"]:
                raise ValueError(
                    f"GROQ_API_KEY missing or malformed (got: {keys['groq_key']}). "
                    "Must start with 'gsk_'. Get one free at console.groq.com."
                )
            result   = run_groq_fallback(target)
            provider = "groq-llama3"
        except Exception as e2:
            logger.warning(f"[AGENT] Groq failed: {e2}")
            result   = run_local_fallback(target)
            provider = "local-fallback"

    elapsed = round(time.time() - start, 2)
    logger.info(f"[AGENT] Investigation done in {elapsed}s via {provider}")

    result += f"\n\n_Agent: {provider} | {elapsed}s_"
    return result


# 8.  SINGLETON  (imported by slack_bot.py and main.py)

# Usage:
#   from ChatSecOps_Agent import investigate
#   answer = investigate("evil-domain.tk")