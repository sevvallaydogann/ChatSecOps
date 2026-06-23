# --- 1. GEREKLİ KÜTÜPHANELERİ İÇERİ AKTARMA ---
import os
import json
import logging
import requests
import joblib
import pandas as pd
import ipinfo
import uuid
from datetime import datetime
import socket
import re
from math import log2
from collections import Counter
import time
import ast
import sqlite3
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from google import genai

# --- ÖZEL MODÜLLER ---
from ChatSecOps_Analytics import create_pdf_report
from ChatSecOps_Memory import memory_engine, format_memory_insights, format_similar_domains
from ChatSecOps_Intelligence import intel_engine, enrich_with_osint, format_osint_results
from ChatSecOps_NLQuery import nl_query_engine
from ChatSecOps_Pivot import pivot_engine
from ChatSecOps_URLParser import url_parser
from ChatSecOps_MITRE import mitre_mapper

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# XAI Explainer
try:
    from xai_explainer import ModelExplainer
except Exception as e:
    print(f"❌ [HATA] XAI Explainer: {e}")
    ModelExplainer = None

# Network Kütüphaneleri
try:
    import whois
    import dns.resolver
except ImportError:
    whois = None
    dns = None

# --- DİNAMİK MODEL YAPILANDIRMASI ---
METADATA_PATH = 'model_outputs/chatsecops_model_v2_20260114_203833_metadata.json'
try:
    with open(METADATA_PATH, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    TRAINING_COLUMNS = meta['dataset_info']['feature_names']
    COLUMNS_TO_SCALE = meta['preprocessing']['columns_to_scale']
    TOP_30_TLDS = meta['preprocessing']['top_30_tlds']
except Exception as e:
    print(f"❌ [KRİTİK HATA] Metadata yüklenemedi: {e}")
    TRAINING_COLUMNS, COLUMNS_TO_SCALE, TOP_30_TLDS = [], [], []

if not TOP_30_TLDS:
    TOP_30_TLDS = ['com', 'net', 'online', 'org', 'ru', 'info', 'co.uk']

# --- KURULUM ---
print("[BİLGİ] SOAR Motoru başlatılıyor...")
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_TOKEN       = os.getenv("IPINFO_TOKEN")
GEMINI_API_KEY     = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
GROQ_API_KEY       = os.getenv("GROQ_API_KEY", "").strip().strip('"').strip("'")

app = FastAPI(title="ChatSecOps SOAR Motoru")

# Model yükle
MODEL_PATH  = 'model_outputs/chatsecops_model_v2_20260114_203833.joblib'
SCALER_PATH = 'model_outputs/chatsecops_model_v2_20260114_203833_scaler.joblib'
try:
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    model, scaler = None, None

# ============================================================================
# GEMINI CLIENT (yeni google.genai SDK)
# ============================================================================
_gemini_client = None
try:
    if GEMINI_API_KEY and len(GEMINI_API_KEY) > 10:
        _gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("✅ [GEMINI] Client initialized (google.genai SDK)")
    else:
        logger.warning("⚠️ [GEMINI] API key missing or too short, skipping initialization")
except Exception as e:
    logger.warning(f"⚠️ [GEMINI] Client initialization failed: {e}")

# XAI yükle
if ModelExplainer:
    try:
        xai_explainer = ModelExplainer(MODEL_PATH)
    except:
        xai_explainer = None
else:
    xai_explainer = None

# IPInfo yükle
try:
    ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)
except:
    ipinfo_handler = None

# =============================================================================
# YARDIMCI FONKSİYONLAR
# =============================================================================
def get_virustotal_data(domain: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except:
        pass
    return {"hata": "Veri bulunamadı"}

def get_abuseipdb_data(ip: str):
    if not ip or ip == "N/A":
        return {"hata": "No IP"}
    url     = 'https://api.abuseipdb.com/api/v2/check'
    params  = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports":         data.get("totalReports")
            }
    except:
        pass
    return {"hata": "Veri bulunamadı"}

def get_ip_from_domain(domain: str):
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        return socket.gethostbyname(domain)
    except:
        pass
    if dns:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            for rdata in resolver.resolve(domain, 'A'):
                return rdata.to_text()
        except:
            pass
    try:
        r = requests.get(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5
        )
        for ans in r.json().get("Answer", []):
            if ans["type"] == 1:
                return ans["data"]
    except:
        pass
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=5)
        for ans in r.json().get("Answer", []):
            if ans["type"] == 1:
                return ans["data"]
    except:
        pass
    return None

def get_network_features(ip: str) -> dict:
    if not ipinfo_handler or not ip:
        return {"CountryCode": "Unknown", "ASN": -1}
    try:
        details = ipinfo_handler.getDetails(ip)
        asn_str = getattr(details, 'asn', '-1').replace('AS', '')
        return {
            "CountryCode": getattr(details, 'country', 'Unknown'),
            "ASN": int(asn_str) if asn_str.isdigit() else -1
        }
    except:
        return {"CountryCode": "Unknown", "ASN": -1}

def calculate_shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0; str_len = len(data); counts = Counter(data)
    for c in counts.values():
        p = c / str_len
        entropy -= p * log2(p)
    return entropy

def get_dns_features(domain: str) -> dict:
    features = {
        'DNSRecordType': 'Unknown', 'MXDnsResponse': False,
        'TXTDnsResponse': False, 'HasSPFInfo': False
    }
    if not dns: return features
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2; resolver.lifetime = 2
    try:
        resolver.resolve(domain, 'A'); features['DNSRecordType'] = 'A'
    except:
        try: resolver.resolve(domain, 'CNAME'); features['DNSRecordType'] = 'CNAME'
        except: pass
    try: resolver.resolve(domain, 'MX'); features['MXDnsResponse'] = True
    except: pass
    try:
        txt = resolver.resolve(domain, 'TXT'); features['TXTDnsResponse'] = True
        if any('v=spf1' in str(r).lower() for r in txt): features['HasSPFInfo'] = True
    except: pass
    return features

def get_whois_features(domain: str) -> dict:
    features = {"CreationDate": -1, "LastUpdateDate": -1, "RegisteredCountry": "Unknown"}
    if not whois: return features
    try:
        w = whois.whois(domain)
        if w.creation_date:
            cd = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            features['CreationDate'] = int(cd.timestamp())
        if w.last_updated:
            lu = w.last_updated[0] if isinstance(w.last_updated, list) else w.last_updated
            features['LastUpdateDate'] = int(lu.timestamp())
        if w.registrant_country:
            features['RegisteredCountry'] = w.registrant_country.strip()
    except:
        pass
    return features

def get_live_features_for_model(domain: str):
    ip_address      = get_ip_from_domain(domain)
    network_features = get_network_features(ip_address) if ip_address else {"CountryCode": "Unknown", "ASN": -1}
    ip_int = -1
    if ip_address:
        try:
            ip_int = int(''.join([f"{int(x):08b}" for x in ip_address.split('.')]), 2)
        except:
            pass
    dns_f   = get_dns_features(domain)
    whois_f = get_whois_features(domain)
    features = {
        'DomainLength':        len(domain),
        'Entropy':             calculate_shannon_entropy(domain),
        'NumericRatio':        len(re.findall(r"[0-9]", domain)) / len(domain),
        'VowelRatio':          len(re.findall(r"[aeiouAEIOU]", domain)) / len(domain),
        'ConsoantRatio':       len(re.findall(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]", domain)) / len(domain),
        'SpecialCharRatio':    len(re.findall(r"[^a-zA-Z0-9.\-]", domain)) / len(domain),
        'TLD_Grouped':         domain.split('.')[-1] if domain.split('.')[-1] in TOP_30_TLDS else 'TLD_Other',
        'Ip':                  ip_int,
        'CountryCode':         network_features['CountryCode'],
        'ASN':                 network_features['ASN'],
        'DNSRecordType':       dns_f['DNSRecordType'],
        'MXDnsResponse':       dns_f['MXDnsResponse'],
        'TXTDnsResponse':      dns_f['TXTDnsResponse'],
        'HasSPFInfo':          dns_f['HasSPFInfo'],
        'RegisteredCountry':   whois_f['RegisteredCountry'],
        'CreationDate':        whois_f['CreationDate'],
        'LastUpdateDate':      whois_f['LastUpdateDate'],
        'StrangeCharacters': 0, 'SubdomainNumber': domain.count('.'),
        'EntropyOfSubDomains': 0, 'ConsoantSequence': 0,
        'VowelSequence': 0, 'NumericSequence': 0, 'SpecialCharSequence': 0,
        'HttpResponseCode': -1, 'DomainInAlexaDB': False,
        'CommonPorts': False, 'HasDkimInfo': False, 'HasDmarcInfo': False,
        'IpReputation': 0, 'DomainReputation': 0
    }
    return features, ip_address

def get_kendi_risk_skorumuz(domain: str) -> dict:
    if not model: return {"hata": "Model yüklenemedi"}
    try:
        live_features, ip = get_live_features_for_model(domain)
        df = pd.DataFrame([live_features])
        df = pd.get_dummies(df, columns=['DNSRecordType', 'CountryCode', 'RegisteredCountry', 'TLD_Grouped'], dtype=int)
        final_df = df.reindex(columns=TRAINING_COLUMNS, fill_value=0)
        final_df[COLUMNS_TO_SCALE] = scaler.transform(final_df[COLUMNS_TO_SCALE])
        final_df.columns = [re.sub(r'[^A-Za-z0-9_]+', '', col) for col in final_df.columns]
        prob       = model.predict_proba(final_df)[0][1] * 100
        prediction = model.predict(final_df)[0]
        explanation_data = None
        if xai_explainer:
            try:
                raw_xai = xai_explainer.generate_explanation(final_df.copy())
                if isinstance(raw_xai, dict):
                    combined = []
                    for f in raw_xai.get('top_5_positive_features', []):
                        combined.append({'feature': f['feature'], 'shap_value': f['shap_value'], 'impact': 'positive'})
                    for f in raw_xai.get('top_5_negative_features', []):
                        combined.append({'feature': f['feature'], 'shap_value': f['shap_value'], 'impact': 'negative'})
                    explanation_data = {'top_features': combined}
            except:
                pass
        return {
            "risk_skoru_yuzde":   f"{prob:.2f}%",
            "tespit_edilen_ip":   ip,
            "tespit_edilen_ulke": live_features['CountryCode'],
            "xai_aciklama":       explanation_data if explanation_data else {"hata": "XAI yok", "top_features": []},
            "model_input_df":     final_df
        }
    except Exception as e:
        return {"hata": str(e)}

def generate_fallback_summary(domain: str, vt: dict, abuse: dict, model_res: dict) -> dict:
    try:
        ml_score = float(model_res.get("risk_skoru_yuzde", "0").replace("%", ""))
    except:
        ml_score = 0
    vt_malicious  = vt.get("malicious", 0) if vt and "hata" not in vt else 0
    vt_total      = sum(vt.values()) if vt and "hata" not in vt else 0
    vt_percentage = (vt_malicious / vt_total * 100) if vt_total > 0 else 0
    abuse_score   = abuse.get("abuseConfidenceScore", 0) if abuse and "hata" not in abuse else 0
    
    if vt_malicious >= 5 or abuse_score >= 70:
        verdict, action, final_score = "MALICIOUS", "BLOCK IMMEDIATELY", max(vt_percentage, abuse_score, ml_score)
    elif vt_malicious >= 2 or abuse_score >= 40 or ml_score >= 50:
        verdict, action, final_score = "SUSPICIOUS", "MONITOR CLOSELY", max(vt_percentage, abuse_score, ml_score)
    else:
        verdict, action, final_score = "SAFE", "NO ACTION REQUIRED", ml_score
        
    parts = []
    if vt_malicious > 0:
        parts.append(f"VirusTotal detected {vt_malicious} out of {vt_total} security vendors flagging this domain as malicious.")
    else:
        parts.append("VirusTotal shows no security vendor flags.")
    if abuse_score > 0:
        parts.append(f"AbuseIPDB reports an abuse confidence score of {abuse_score}%, indicating potential malicious activity.")
    parts.append(f"Our machine learning model calculated a behavioral risk score of {ml_score:.1f}%.")
    parts.append(f"Based on the combined threat intelligence, the domain is classified as {verdict}. Recommended action: {action}.")
    
    return {
        "verdict":    verdict,
        "action":     action,
        "risk_score": f"{final_score:.1f}%",
        "xai_output": " ".join(parts)
    }

# =============================================================================
# MULTI-LLM ROUTER  (Gemini → Groq → OpenAI → local fallback)
# =============================================================================
def _call_gemini(prompt: str) -> str | None:
    """Call Gemini using the new google.genai SDK."""
    if not _gemini_client:
        return None
    try:
        response = _gemini_client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt,
        )
        return response.text or None
    except Exception as e:
        logger.warning(f"⚠️ [MAIN ROUTER] Gemini failed: {str(e)[:80]}")
        return None

def _call_groq(prompt: str) -> str | None:
    """Call Groq Llama-3."""
    if not GROQ_API_KEY:
        return None
    try:
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 512,
        }
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        }
        res = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            json=payload, headers=headers, timeout=15
        )
        if res.status_code == 200:
            return res.json()["choices"][0]["message"]["content"]
        logger.warning(f"⚠️ [MAIN ROUTER] Groq returned HTTP {res.status_code}")
    except Exception as e:
        logger.warning(f"⚠️ [MAIN ROUTER] Groq failed: {str(e)[:80]}")
    return None

def _call_openai(prompt: str) -> str | None:
    """Call OpenAI GPT-4o-mini."""
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not openai_key:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=openai_key)
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            timeout=15
        )
        return completion.choices[0].message.content
    except Exception as e:
        logger.warning(f"⚠️ [MAIN ROUTER] OpenAI failed: {str(e)[:80]}")
    return None

def llm_summarize(prompt: str) -> tuple[str | None, bool]:
    """
    Try LLM providers in order. Returns (summary_text, is_fallback).
    summary_text is None only if all providers failed.
    """
    logger.info("[MAIN ROUTER] Requesting summary from Gemini...")
    result = _call_gemini(prompt)
    if result:
        logger.info("✅ [MAIN ROUTER] Gemini succeeded.")
        return result, False
        
    logger.info("[MAIN ROUTER] Gemini unavailable — trying Groq (Llama-3.3)...")
    result = _call_groq(prompt)
    if result:
        logger.info("✅ [MAIN ROUTER] Groq succeeded.")
        return result, False
        
    logger.info("[MAIN ROUTER] Groq unavailable — trying OpenAI...")
    result = _call_openai(prompt)
    if result:
        logger.info("✅ [MAIN ROUTER] OpenAI succeeded.")
        return result, False
        
    logger.info("🔄 [MAIN ROUTER] All external providers exhausted. Using local fallback.")
    return None, True

# =============================================================================
# ANA ENDPOINT
# =============================================================================
@app.get("/enrich-and-summarize/domain/{domain_name}")
def enrich_and_summarize_domain(domain_name: str):
    logger.info(f"ANALIZ: {domain_name}")
    start_time = time.time()
    
    mem   = memory_engine.get_domain_insights(domain_name)
    camp  = memory_engine.get_campaign_detection(domain_name)
    vt    = get_virustotal_data(domain_name)
    model_res = get_kendi_risk_skorumuz(domain_name)
    ip    = model_res.get("tespit_edilen_ip")
    abuse = get_abuseipdb_data(ip)
    
    try:
        osint = intel_engine.get_full_intel(domain_name, ip)
    except:
        osint = {}
        
    shap_file = None
    if xai_explainer and "model_input_df" in model_res:
        try:
            shap_file = xai_explainer.generate_shap_waterfall(model_res["model_input_df"], domain_name)
        except:
            pass
            
    try:
        risk_score_num = float(model_res.get('risk_skoru_yuzde', '0').replace('%', ''))
    except:
        risk_score_num = 0.0
        
    # ── LLM summary ──────────────────────────────────────────────────────────
    prompt = f"""You are a SOC analyst. Analyze this domain security data:
TARGET: {domain_name}
THREAT INTELLIGENCE:
- VirusTotal: {vt.get('malicious', 0)}/{sum(vt.values()) if vt and 'hata' not in vt else 0} vendors flagged
- AbuseIPDB Confidence: {abuse.get('abuseConfidenceScore', 'N/A')}%
- ML Risk Score: {model_res.get('risk_skoru_yuzde')}
- IP: {ip} ({model_res.get('tespit_edilen_ulke', 'Unknown')})
Write a concise 3-sentence summary: verdict, evidence, and recommended action. Do not truncate."""

    ai_summary_text, gemini_failed = llm_summarize(prompt)
    if ai_summary_text:
        ai_summary = ai_summary_text
    else:
        ai_summary = generate_fallback_summary(domain_name, vt, abuse, model_res)
    # ─────────────────────────────────────────────────────────────────────────
    
    pdf_text = ai_summary.get("xai_output", "Analysis Unavailable") if isinstance(ai_summary, dict) else str(ai_summary)
    pdf_path = create_pdf_report(
        domain=domain_name,
        ai_summary=pdf_text,
        risk_score=risk_score_num,
        vt_stats=vt,
        abuse_data=abuse,
        osint_data=osint,
        shap_path=shap_file
    )
    
    response = {
        "domain":       domain_name,
        "ai_ozeti":     ai_summary,
        "ham_veriler":  {
            "virustotal":    vt,
            "abuseipdb":     abuse,
            "kendi_modelimiz": model_res,
            "osint":         osint
        },
        "memory_insights":  mem,
        "campaign_alert":   camp,
        "pdf_report":       pdf_path,
        "shap_graph":       shap_file,
        "processing_time":  round(time.time() - start_time, 2),
        "ai_provider":      "fallback" if gemini_failed else "router"
    }
    
    if "model_input_df" in response["ham_veriler"]["kendi_modelimiz"]:
        del response["ham_veriler"]["kendi_modelimiz"]["model_input_df"]
        
    memory_engine.store_analysis(domain_name, response)
    
    # Feature 2: IOC Pivot (DÖNGÜ KORUMALI)
    ip = response["ham_veriler"]["kendi_modelimiz"].get("tespit_edilen_ip")
    if ip and ip != "N/A":
        try:
            # 💡 ÇÖZÜM: DB geçmişine bakarak sonsuz döngü kontrolü yapıyoruz.
            # Eğer son 5 dakika içinde bu IP üzerinden bir pivot çalıştıysa 
            # veya aranan domain zaten incelenmişse pivotu tetiklemiyoruz.
            conn = sqlite3.connect("chatsecops_memory.db")
            cursor = conn.cursor()
            
            # chatsecops_memory.db şemasına uygun tablodan kontrol (Son 5 dakika)
            cursor.execute("""
                SELECT COUNT(*) FROM domain_analysis 
                WHERE (domain = ? OR ip_address = ?) 
                AND timestamp >= datetime('now', '-5 minutes')
            """, (domain_name, ip))
            
            already_analyzed_count = cursor.fetchone()[0]
            conn.close()
            
            # bit.ly ile www.bit.ly varyasyonlarının birbirini sonsuz tetiklemesini engelleme kuralı
            base_domain = domain_name.replace("www.", "")
            is_self_loop = any(k in base_domain for k in ["bit.ly"]) # Kritik altyapı/kısaltma istisnası
            
            if already_analyzed_count > 1 or (already_analyzed_count >= 1 and is_self_loop):
                logger.info(f"[PIVOT] 🛑 Sonsuz döngü veya mükerrer analiz algılandı! Pivot engellendi: {domain_name} ({ip})")
                response["pivot_chain"] = {
                    "triggered": False, 
                    "reason": "Sonsuz döngü (Loop Protection) koruması tetiklendi."
                }
            else:
                pivot_result = pivot_engine.run_pivot(
                    trigger_domain=domain_name,
                    ip_address=ip,
                    trigger_risk_score=risk_score_num
                )
                response["pivot_chain"] = {
                    "triggered":          pivot_result["pivot_triggered"],
                    "ip_address":         pivot_result["ip_address"],
                    "total_related":      pivot_result["total_related"],
                    "auto_analyzed_count": len(pivot_result["auto_analyzed"])
                }
                if pivot_result["pivot_triggered"] and pivot_result["slack_message"]:
                    _send_pivot_to_slack(pivot_result["slack_message"])
        except Exception as e:
            logger.error(f"[PIVOT] Pivot analizi başlatılamadı: {e}")
            response["pivot_chain"] = {"triggered": False, "error": str(e)}
    else:
        response["pivot_chain"] = {"triggered": False, "reason": "IP tespit edilemedi"}
        
    # Feature 5: MITRE ATT&CK
    try:
        mitre_result = mitre_mapper.map(response)
        response["mitre_attack"] = mitre_result
        logger.info(f"[MITRE] {len(mitre_result['techniques'])} teknik eşleşti: {[t['technique_id'] for t in mitre_result['techniques']]}")
    except Exception as e:
        logger.error(f"[MITRE] Eşleştirme hatası: {e}")
        response["mitre_attack"] = {"techniques": [], "total_triggered": 0}
        
    logger.info(f"✅ Analiz tamamlandı ({response['processing_time']}s) - AI Status: {response['ai_provider']}")
    return response

# =============================================================================
# DİĞER ENDPOINTLER
# =============================================================================
@app.get("/")
def read_root():
    return {"status": "ChatSecOps API is running", "docs_url": "/docs"}

@app.get("/statistics")
def get_stats():
    return {"status": "success", "data": memory_engine.get_statistics()}

def _send_pivot_to_slack(message: str):
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
    if slack_webhook:
        try:
            requests.post(slack_webhook, json={"text": message}, timeout=5)
        except Exception as e:
            logger.warning(f"[PIVOT] Slack webhook hatası: {e}")
    else:
        logger.info("[PIVOT] Slack webhook bulunamadı, bot üzerinden iletilecek")

@app.get("/pivot/{domain_name}")
def get_pivot_chain(domain_name: str):
    logger.info(f"[PIVOT] Manuel pivot isteği: {domain_name}")
    conn = sqlite3.connect("chatsecops_memory.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT ip_address FROM domain_analysis WHERE domain = ? ORDER BY timestamp DESC LIMIT 1",
        (domain_name,)
    )
    row = cursor.fetchone()
    conn.close()
    
    ip = row[0] if row else None
    if not ip or ip == "N/A":
        ip = get_ip_from_domain(domain_name)
    if not ip:
        raise HTTPException(status_code=404, detail=f"{domain_name} için IP adresi tespit edilemedi.")
        
    risk_score = 0.0
    conn = sqlite3.connect("chatsecops_memory.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT risk_score FROM domain_analysis WHERE domain = ? ORDER BY timestamp DESC LIMIT 1",
        (domain_name,)
    )
    r = cursor.fetchone()
    conn.close()
    if r: risk_score = r[0]
    
    pivot_result = pivot_engine.run_pivot(
        trigger_domain=domain_name,
        ip_address=ip,
        trigger_risk_score=risk_score
    )
    return {"domain": domain_name, "ip_address": ip, "pivot_result": pivot_result}

# ============================================================================
# FEATURE 1: PHISHING URL ANALİZİ
# ============================================================================
@app.get("/analyze-url")
def analyze_url(url: str):
    logger.info(f"[URL] Gelen URL: {url}")
    url_analysis     = url_parser.analyze(url)
    extracted_domain = url_analysis["extracted_domain"]
    logger.info(f"[URL] Çıkarılan domain: {extracted_domain}")
    
    if not extracted_domain:
        raise HTTPException(status_code=400, detail="URL'den domain çıkarılamadı.")
        
    domain_result = enrich_and_summarize_domain(extracted_domain)
    try:
        ml_score = float(
            domain_result["ham_veriler"]["kendi_modelimiz"]
            .get("risk_skoru_yuzde", "0").replace("%", "")
        )
    except:
        ml_score = 0.0
        
    url_boost      = url_analysis["url_risk_boost"]
    combined_score = min(100.0, ml_score + url_boost)
    url_risk_level = url_analysis["risk_level"]
    
    if url_risk_level == "CRITICAL" or combined_score >= 80:
        combined_verdict = "CRITICAL"
    elif url_risk_level == "HIGH" or combined_score >= 60:
        combined_verdict = "MALICIOUS"
    elif url_risk_level == "MEDIUM" or combined_score >= 40:
        combined_verdict = "SUSPICIOUS"
    else:
        combined_verdict = "SAFE"
        
    # URL-specific LLM summary
    url_ai_summary = None
    if url_analysis["findings"]:
        url_prompt = f"""You are a SOC analyst. Summarize these URL analysis findings in 2-3 sentences (English, professional):
URL: {url}
Domain Risk Score: {ml_score:.1f}%
URL Structural Risk Boost: +{url_boost}
Combined Final Score: {combined_score:.1f}%
Findings:
{chr(10).join(url_analysis["findings"])}"""
        url_ai_summary, _ = llm_summarize(url_prompt)
        
    if not url_ai_summary:
        url_ai_summary = url_analysis["summary"]
        
    domain_result["url_analysis"] = {
        "original_url":     url,
        "normalized_url":   url_analysis["normalized_url"],
        "extracted_domain": extracted_domain,
        "components":       url_analysis["components"],
        "url_risk_boost":   url_boost,
        "url_risk_level":   url_analysis["risk_level"],
        "findings":         url_analysis["findings"],
        "url_summary":      url_ai_summary,
    }
    domain_result["combined_score"]   = f"{combined_score:.1f}%"
    domain_result["combined_verdict"] = combined_verdict
    domain_result["analysis_type"]    = "full_url"
    
    try:
        mitre_result = mitre_mapper.map(domain_result)
        domain_result["mitre_attack"] = mitre_result
        logger.info(f"[MITRE/URL] {len(mitre_result['techniques'])} teknik eşleşti")
    except Exception as e:
        logger.error(f"[MITRE/URL] Hata: {e}")
        
    logger.info(f"[URL] Tamamlandı: ML={ml_score:.1f}% + URL={url_boost} = {combined_score:.1f}% ({combined_verdict})")
    return domain_result

# ============================================================================
# FEATURE 4: DOĞAL DİL SORGU ARAYÜZÜ
# ============================================================================
@app.get("/agent/ask")
def ask_ai_agent(query: str):
    logger.info(f"🤖 AGENT SORGUSU: {query}")
    if not query or not query.strip():
        raise HTTPException(status_code=400, detail="Soru boş olamaz.")
        
    result = nl_query_engine.ask(query.strip())
    return {
        "question":      query,
        "answer":        result["answer"],
        "sql_generated": result["sql"],
        "row_count":     result["row_count"],
        "success":       result["success"]
    }