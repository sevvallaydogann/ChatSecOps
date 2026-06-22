# --- 1. GEREKLİ KÜTÜPHANELERİ İÇERİ AKTARMA ---
import os
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
import json
import logging
import ast
import sqlite3

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import google.generativeai as genai

# --- ÖZEL MODÜLLER ---
from ChatSecOps_Analytics import create_pdf_report 
from ChatSecOps_Memory import memory_engine, format_memory_insights, format_similar_domains
from ChatSecOps_Intelligence import intel_engine, enrich_with_osint, format_osint_results 
from ChatSecOps_NLQuery import nl_query_engine
from ChatSecOps_Pivot import pivot_engine

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# XAI Explainer
try:
    from xai_explainer import ModelExplainer
except Exception as e:
    logger.error(f"❌ [HATA] XAI Explainer yüklenemedi: {e}")
    ModelExplainer = None

# Network Kütüphaneleri
try:
    import whois
    import dns.resolver
except ImportError:
    whois = None
    dns = None

# --- [DİNAMİK MODEL YAPILANDIRMASI] ---
METADATA_PATH = 'model_outputs/chatsecops_model_v2_20260609_220654_metadata.json'
try:
    with open(METADATA_PATH, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    TRAINING_COLUMNS = meta['dataset_info']['feature_names']
    COLUMNS_TO_SCALE = meta['preprocessing']['columns_to_scale']
    TOP_30_TLDS = meta['preprocessing']['top_30_tlds']
except Exception as e:
    logger.error(f"❌ [KRİTİK HATA] Metadata yüklenemedi: {e}")
    TRAINING_COLUMNS, COLUMNS_TO_SCALE, TOP_30_TLDS = [], [], []

if not TOP_30_TLDS:
    TOP_30_TLDS = ['com', 'net', 'online', 'org', 'ru', 'info', 'co.uk']

# --- 2. KURULUM ---
logger.info("[BİLGİ] SOAR Motoru başlatılıyor...")
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

app = FastAPI(title="ChatSecOps SOAR Motoru")

# Modeli Yükle
MODEL_PATH = 'model_outputs/chatsecops_model_v2_20260609_220654.joblib'
SCALER_PATH = 'model_outputs/chatsecops_model_v2_20260609_220654_scaler.joblib'
try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    logger.info("✅ [ML] LightGBM Modeli ve Scaler başarıyla yüklendi.")
except Exception as e:
    logger.error(f"❌ [ML] Model yükleme hatası: {e}")
    model, scaler = None, None

# ============================================================================
# GEMİNİ YÜKLEME - EN GÜNCEL STABİL SÜRÜMLER
# ============================================================================
try:
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY .env dosyasında bulunamadı!")
    
    genai.configure(api_key=GEMINI_API_KEY)
    available_models = genai.list_models()
    model_names = [m.name for m in available_models if 'generateContent' in m.supported_generation_methods]
    
    # Bilimsel yayın ve kararlılık için 2.5 ve 1.5 sürümlerini önceliklendiriyoruz
    model_priority = [
        'models/gemini-2.5-flash',
        'models/gemini-1.5-flash-latest',
        'models/gemini-1.5-flash',
        'models/gemini-pro'
    ]
    
    if not any(m in model_names for m in model_priority):
        model_priority = [model_names[0]] if model_names else []
    
    gemini_model = None
    for model_name in model_priority:
        try:
            logger.info(f" 📡 Gemini deneniyor: {model_name}")
            test_model = genai.GenerativeModel(model_name)
            test_response = test_model.generate_content("Hello")
            gemini_model = test_model
            logger.info(f"✅ [GEMINI] Aktif model: {model_name}")
            break
        except Exception as e:
            logger.warning(f" ⚠️ {model_name} başarısız: {str(e)[:50]}")
            continue
            
except Exception as e:
    logger.error(f"❌ [GEMINI] Kritik hata: {e}")
    gemini_model = None

if ModelExplainer and MODEL_PATH:
    try:
        xai_explainer = ModelExplainer(MODEL_PATH)
    except:
        xai_explainer = None
else:
    xai_explainer = None

ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN) if IPINFO_TOKEN else None


# --- 3. YARDIMCI FONKSİYONLAR ---
def get_virustotal_data(domain: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    except: pass
    return {"hata": "Veri bulunamadı"}

def get_abuseipdb_data(ip: str):
    if not ip or ip == "N/A": return {"hata": "No IP"}
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {"abuseConfidenceScore": data.get("abuseConfidenceScore"), "totalReports": data.get("totalReports")}
    except: pass
    return {"hata": "Veri bulunamadı"}

def get_ip_from_domain(domain: str) -> str | None:
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        return socket.gethostbyname(domain)
    except: pass

    if dns:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            answers = resolver.resolve(domain, 'A')
            for rdata in answers: return rdata.to_text()
        except: pass

    for doh_url in ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]:
        try:
            url = f"{doh_url}?name={domain}&type=A"
            headers = {"Accept": "application/dns-json"} if "cloudflare" in doh_url else {}
            response = requests.get(url, headers=headers, timeout=5)
            data = response.json()
            if "Answer" in data:
                for answer in data["Answer"]:
                    if answer["type"] == 1: return answer["data"]
        except: pass
    return None

def get_network_features(ip: str) -> dict:
    if not ipinfo_handler or not ip: return {"CountryCode": "Unknown", "ASN": -1}
    try:
        details = ipinfo_handler.getDetails(ip)
        asn_str = getattr(details, 'asn', '-1').replace('AS', '')
        return {"CountryCode": getattr(details, 'country', 'Unknown'), "ASN": int(asn_str) if asn_str.isdigit() else -1}
    except: return {"CountryCode": "Unknown", "ASN": -1}

def calculate_shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0; str_len = len(data); counts = Counter(data)
    for char_count in counts.values():
        p_x = char_count / str_len; entropy -= p_x * log2(p_x)
    return entropy

def get_dns_features(domain: str) -> dict:
    features = {'DNSRecordType': 'Unknown', 'MXDnsResponse': False, 'TXTDnsResponse': False, 'HasSPFInfo': False}
    if not dns: return features
    resolver = dns.resolver.Resolver(); resolver.timeout = 2; resolver.lifetime = 2
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
        if w.creation_date: features['CreationDate'] = int((w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date).timestamp())
        if w.last_updated: features['LastUpdateDate'] = int((w.last_updated[0] if isinstance(w.last_updated, list) else w.last_updated).timestamp())
        if w.registrant_country: features['RegisteredCountry'] = w.registrant_country.strip()
    except: pass
    return features

def get_live_features_for_model(domain: str):
    ip_address = get_ip_from_domain(domain)
    network_features = get_network_features(ip_address) if ip_address else {"CountryCode": "Unknown", "ASN": -1}
    ip_int = -1
    if ip_address:
        try: ip_int = int(''.join([f"{int(x):08b}" for x in ip_address.split('.')]), 2)
        except: pass
        
    dns_f = get_dns_features(domain)
    whois_f = get_whois_features(domain)
    
    features = {
        'DomainLength': len(domain),
        'Entropy': calculate_shannon_entropy(domain),
        'NumericRatio': len(re.findall(r"[0-9]", domain)) / len(domain),
        'VowelRatio': len(re.findall(r"[aeiouAEIOU]", domain)) / len(domain),
        'ConsoantRatio': len(re.findall(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]", domain)) / len(domain),
        'SpecialCharRatio': len(re.findall(r"[^a-zA-Z0-9.\-]", domain)) / len(domain),
        'TLD_Grouped': domain.split('.')[-1] if domain.split('.')[-1] in TOP_30_TLDS else 'TLD_Other',
        'Ip': ip_int,
        'CountryCode': network_features['CountryCode'],
        'ASN': network_features['ASN'],
        'DNSRecordType': dns_f['DNSRecordType'],
        'MXDnsResponse': dns_f['MXDnsResponse'],
        'TXTDnsResponse': dns_f['TXTDnsResponse'],
        'HasSPFInfo': dns_f['HasSPFInfo'],
        'RegisteredCountry': whois_f['RegisteredCountry'],
        'CreationDate': whois_f['CreationDate'],
        'LastUpdateDate': whois_f['LastUpdateDate'],
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
        
        final_df = pd.DataFrame(columns=TRAINING_COLUMNS)
        final_df = df.reindex(columns=TRAINING_COLUMNS, fill_value=0)
        final_df[COLUMNS_TO_SCALE] = scaler.transform(final_df[COLUMNS_TO_SCALE])
        final_df.columns = [re.sub(r'[^A-Za-z0-9_]+', '', col) for col in final_df.columns]
        
        prob = model.predict_proba(final_df)[0][1] * 100
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
            except: pass
            
        return {
            "risk_skoru_yuzde": f"{prob:.2f}%",
            "tahmin_sinifi": int(prediction),
            "tespit_edilen_ip": ip,
            "tespit_edilen_ulke": live_features['CountryCode'],
            "xai_aciklama": explanation_data if explanation_data else {"hata": "XAI yok", "top_features": []},
            "model_input_df": final_df
        }
    except Exception as e:
        return {"hata": str(e)}

def generate_fallback_summary(domain: str, vt: dict, abuse: dict, model: dict) -> dict:
    score_str = model.get("risk_skoru_yuzde", "0")
    try: ml_score = float(score_str.replace("%", ""))
    except: ml_score = 0
    
    vt_malicious = vt.get("malicious", 0) if vt and "hata" not in vt else 0
    vt_total = sum(vt.values()) if vt and "hata" not in vt else 0
    vt_percentage = (vt_malicious / vt_total * 100) if vt_total > 0 else 0
    abuse_score = abuse.get("abuseConfidenceScore", 0) if abuse and "hata" not in abuse else 0
    
    if vt_malicious >= 5 or abuse_score >= 70:
        verdict = "MALICIOUS"; action = "BLOCK IMMEDIATELY"
        final_score = max(vt_percentage, abuse_score, ml_score)
    elif vt_malicious >= 2 or abuse_score >= 40 or ml_score >= 50:
        verdict = "SUSPICIOUS"; action = "MONITOR CLOSELY"
        final_score = max(vt_percentage, abuse_score, ml_score)
    else:
        verdict = "SAFE"; action = "NO ACTION REQUIRED"; final_score = ml_score
    
    explanation = f"VirusTotal: {vt_malicious}/{vt_total}. AbuseIPDB Score: {abuse_score}%. ML Score: {ml_score:.1f}%. Verdict: {verdict}."
    return {"verdict": verdict, "action": action, "risk_score": f"{final_score:.1f}%", "xai_output": explanation}

# --- 4. ANA ENDPOINT (ZENGİNLEŞTİRME VE ANALİZ) ---
@app.get("/enrich-and-summarize/domain/{domain_name}")
def enrich_and_summarize_domain(domain_name: str):
    logger.info(f"🚨 ANALIZ TETİKLENDİ: {domain_name}")
    start_time = time.time()

    mem = memory_engine.get_domain_insights(domain_name)
    camp = memory_engine.get_campaign_detection(domain_name)
    vt = get_virustotal_data(domain_name)
    model_res = get_kendi_risk_skorumuz(domain_name)
    ip = model_res.get("tespit_edilen_ip")
    abuse = get_abuseipdb_data(ip)
    
    try: osint = intel_engine.get_full_intel(domain_name, ip)
    except: osint = {}

    shap_file = None
    if xai_explainer and "model_input_df" in model_res:
        try: shap_file = xai_explainer.generate_shap_waterfall(model_res["model_input_df"], domain_name)
        except: pass

    try: risk_score_num = float(model_res.get('risk_skoru_yuzde', '0').replace('%', ''))
    except: risk_score_num = 0.0
    
    prompt = f"You are a SOC analyst. Analyze this domain security data:\nTARGET: {domain_name}\nVirusTotal: {vt.get('malicious', 0)} vendors flagged\nAbuseIPDB Confidence: {abuse.get('abuseConfidenceScore', 'N/A')}%\nML Risk Score: {model_res.get('risk_skoru_yuzde')}\nIP: {ip}\nWrite 3-4 sentences explaining verdict, evidence, and recommended action."

    ai_summary = None
    gemini_failed = False
    
    if gemini_model:
        for attempt in range(3):
            try:
                response = gemini_model.generate_content(prompt)
                if hasattr(response, 'text') and response.text:
                    ai_summary = response.text
                    break
            except Exception as e:
                if attempt == 2: gemini_failed = True
                time.sleep(1)
    else:
        gemini_failed = True
    
    if gemini_failed or ai_summary is None:
        ai_summary = generate_fallback_summary(domain_name, vt, abuse, model_res)
    
    pdf_text = ai_summary.get("xai_output", "Analysis Unavailable") if isinstance(ai_summary, dict) else str(ai_summary)
    
    pdf_path = create_pdf_report(
        domain=domain_name, ai_summary=pdf_text, risk_score=risk_score_num,
        vt_stats=vt, abuse_data=abuse, osint_data=osint, shap_path=shap_file
    )

    response = {
        "domain": domain_name,
        "ai_ozeti": ai_summary,
        "ham_veriler": {
            "virustotal": vt, "abuseipdb": abuse,
            "kendi_modelimiz": model_res, "osint": osint
        },
        "memory_insights": mem,
        "campaign_alert": camp,
        "pdf_report": pdf_path,
        "shap_graph": shap_file,
        "processing_time": round(time.time() - start_time, 2),
        "ai_provider": "gemini" if not gemini_failed else "fallback"
    }
    
    if "model_input_df" in response["ham_veriler"]["kendi_modelimiz"]:
        del response["ham_veriler"]["kendi_modelimiz"]["model_input_df"]
    
    # Belleğe kaydet
    memory_engine.store_analysis(domain_name, response)
    
    # ----------------===============================================----------------
    # FIX: STRING OLARAK UNUTULAN INTEGRATION AKTİF EDİLDİ (FEATURE 2)
    # ----------------===============================================----------------
    if ip and ip != "N/A":
        try:
            pivot_result = pivot_engine.run_pivot(
                trigger_domain=domain_name,
                ip_address=ip,
                trigger_risk_score=risk_score_num
            )
            response["pivot_chain"] = {
                "triggered": pivot_result["pivot_triggered"],
                "ip_address": pivot_result["ip_address"],
                "total_related": pivot_result["total_related"],
                "auto_analyzed_count": len(pivot_result["auto_analyzed"])
            }
            if pivot_result["pivot_triggered"] and pivot_result["slack_message"]:
                _send_pivot_to_slack(pivot_result["slack_message"])
        except Exception as e:
            logger.error(f"[PIVOT] Arka plan pivot analizi hatası: {e}")
            response["pivot_chain"] = {"triggered": False, "error": str(e)}
    else:
        response["pivot_chain"] = {"triggered": False, "reason": "IP adresi co-host analizi için yetersiz."}

    logger.info(f"✅ Analiz tamamlandı ({response['processing_time']}s)")
    return response


@app.get("/")
def read_root():
    return {"status": "ChatSecOps API is running", "docs_url": "/docs"}

@app.get("/statistics")
def get_stats():
    return {"status": "success", "data": memory_engine.get_statistics()}

def _send_pivot_to_slack(message: str):
    slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
    if slack_webhook:
        try: requests.post(slack_webhook, json={"text": message}, timeout=5)
        except Exception as e: logger.warning(f"[PIVOT] Slack Webhook hatası: {e}")
    else:
        logger.info("[PIVOT] Webhook tanımlı değil, loglara yazıldı.")

# FIX: Context Manager kullanılarak güvenli hale getirilmiş Manuel Pivot Endpoint'i
@app.get("/pivot/{domain_name}")
def get_pivot_chain(domain_name: str):
    logger.info(f"[PIVOT] Manuel istek: {domain_name}")
    ip = None
    risk_score = 0.0

    with sqlite3.connect("chatsecops_memory.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address, risk_score FROM domain_analysis WHERE domain = ? ORDER BY timestamp DESC LIMIT 1", (domain_name,))
        row = cursor.fetchone()
        if row:
            ip, risk_score = row[0], row[1]

    if not ip or ip == "N/A":
        ip = get_ip_from_domain(domain_name)
    
    if not ip:
        raise HTTPException(status_code=404, detail="IP adresi çözülemedi.")
    
    pivot_result = pivot_engine.run_pivot(
        trigger_domain=domain_name, ip_address=ip, trigger_risk_score=risk_score
    )
    return {"domain": domain_name, "ip_address": ip, "pivot_result": pivot_result}

# --- FEATURE 4: DOĞAL DİL SORGU ARA YÜZÜ ---
@app.get("/agent/ask")
def ask_ai_agent(query: str):
    logger.info(f"🤖 AGENT: {query}")
    if not query or not query.strip():
        raise HTTPException(status_code=400, detail="Soru boş olamaz.")
    
    result = nl_query_engine.ask(query.strip())
    return {
        "question": query,
        "answer": result["answer"],
        "sql_generated": result["sql"],
        "row_count": result["row_count"],
        "success": result["success"]
    }