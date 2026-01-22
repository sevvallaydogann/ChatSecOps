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
import ast # Güvenli string-to-dict dönüşümü için

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import google.generativeai as genai

# --- ÖZEL MODÜLLER ---
from ChatSecOps_Analytics import create_pdf_report 
from ChatSecOps_Memory import memory_engine, format_memory_insights, format_similar_domains
from ChatSecOps_Intelligence import intel_engine, enrich_with_osint, format_osint_results 

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
    print(f"❌ [HATA] XAI Explainer: {e}")
    ModelExplainer = None

# Network Kütüphaneleri
try:
    import whois
    import dns.resolver
except ImportError:
    whois = None
    dns = None

# --- [DİNAMİK MODEL YAPILANDIRMASI] ---
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

# --- 2. KURULUM ---
print("[BİLGİ] SOAR Motoru başlatılıyor...")
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

app = FastAPI(title="ChatSecOps SOAR Motoru")

# Modeli Yükle
MODEL_PATH = 'model_outputs/chatsecops_model_v2_20260114_203833.joblib'
SCALER_PATH = 'model_outputs/chatsecops_model_v2_20260114_203833_scaler.joblib'

try:
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
except Exception as e:
    model, scaler = None, None

# Gemini Yükle
try:
    genai.configure(api_key=GEMINI_API_KEY)
    # Yeni Satır:
    gemini_model = genai.GenerativeModel('models/gemini-1.5-flash')
except:
    gemini_model = None

# XAI Yükle
if ModelExplainer:
    try:
        xai_explainer = ModelExplainer(MODEL_PATH)
    except:
        xai_explainer = None
else:
    xai_explainer = None

# IPInfo Yükle
try:
    ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)
except:
    ipinfo_handler = None


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

# === [DÜZELTİLDİ] GÜÇLENDİRİLMİŞ IP ÇÖZÜCÜ (4 KATMANLI) ===
def get_ip_from_domain(domain: str) -> str | None:
    """
    4 Farklı yöntemle IP adresi bulmaya çalışır.
    Google.com gibi sitelerde kesin sonuç verir.
    """
    # 1. Temizlik
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
    
    # YÖNTEM 1: Standart Socket
    try:
        return socket.gethostbyname(domain)
    except:
        pass

    # YÖNTEM 2: DNS Lib (Google DNS Zorlamalı)
    if dns:
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                return rdata.to_text()
        except:
            pass

    # YÖNTEM 3: Cloudflare DNS over HTTPS (Port 53 kapalıysa bile çalışır)
    try:
        url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
        headers = {"Accept": "application/dns-json"}
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()
        if "Answer" in data:
            for answer in data["Answer"]:
                if answer["type"] == 1: # A Record
                    return answer["data"]
    except:
        pass

    # YÖNTEM 4: Google DNS over HTTPS (Yedek)
    try:
        url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(url, timeout=5)
        data = response.json()
        if "Answer" in data:
            for answer in data["Answer"]:
                if answer["type"] == 1:
                    return answer["data"]
    except:
        pass

    return None

def get_network_features(ip: str) -> dict:
    if not ipinfo_handler or not ip: return {"CountryCode": "Bilinmiyor", "ASN": -1}
    try:
        details = ipinfo_handler.getDetails(ip)
        asn_str = getattr(details, 'asn', '-1').replace('AS', '')
        return {"CountryCode": getattr(details, 'country', 'Bilinmiyor'), "ASN": int(asn_str) if asn_str.isdigit() else -1}
    except: return {"CountryCode": "Bilinmiyor", "ASN": -1}

def calculate_shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0; str_len = len(data); counts = Counter(data)
    for char_count in counts.values():
        p_x = char_count / str_len; entropy -= p_x * log2(p_x)
    return entropy

def get_dns_features(domain: str) -> dict:
    features = {'DNSRecordType': 'Bilinmiyor', 'MXDnsResponse': False, 'TXTDnsResponse': False, 'HasSPFInfo': False}
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
    features = {"CreationDate": -1, "LastUpdateDate": -1, "RegisteredCountry": "Bilinmiyor"}
    if not whois: return features
    try:
        w = whois.whois(domain) # type: ignore
        if w.creation_date: features['CreationDate'] = int((w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date).timestamp())
        if w.last_updated: features['LastUpdateDate'] = int((w.last_updated[0] if isinstance(w.last_updated, list) else w.last_updated).timestamp())
        if w.registrant_country: features['RegisteredCountry'] = w.registrant_country.strip()
    except: pass
    return features

def get_live_features_for_model(domain: str):
    # IP Resolver'ı burada çağırıyoruz
    ip_address = get_ip_from_domain(domain)
    
    network_features = get_network_features(ip_address) if ip_address else {"CountryCode": "Bilinmiyor", "ASN": -1}
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
        
        # XAI
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
            "tespit_edilen_ip": ip,
            "tespit_edilen_ulke": live_features['CountryCode'],
            "xai_aciklama": explanation_data if explanation_data else {"hata": "XAI yok", "top_features": []},
            "model_input_df": final_df
        }
    except Exception as e:
        return {"hata": str(e)}

def generate_fallback_summary(domain: str, vt: dict, abuse: dict, model: dict) -> dict:
    """Yedek Rapor (JSON döndürür, aşağıda metne çeviririz)"""
    score_str = model.get("risk_skoru_yuzde", "0")
    try: score = float(score_str.replace("%", ""))
    except: score = 0
    
    verdict = "MALICIOUS" if score > 80 else "SUSPICIOUS" if score > 50 else "SAFE"
    
    # PDF için temiz bir İngilizce metin oluştur
    clean_text = (
        f"Automated risk analysis completed. The system calculated a risk score of {score_str}. "
        f"Based on behavioral patterns and threat intelligence feeds, the domain is classified as {verdict}. "
        "No manual review from AI was available at this time, so this is an automated fallback report."
    )
    
    return {
        "verdict": verdict,
        "action": "BLOCK" if verdict == "MALICIOUS" else "MONITOR",
        "risk_score": score_str,
        "xai_output": clean_text # Artık düzgün bir cümle, sözlük değil!
    }

# --- 4. ANA ENDPOINT ---

@app.get("/enrich-and-summarize/domain/{domain_name}")
def enrich_and_summarize_domain(domain_name: str):
    logger.info(f"ANALIZ: {domain_name}")
    start_time = time.time()

    # 1. Veri Toplama
    mem = memory_engine.get_domain_insights(domain_name)
    camp = memory_engine.get_campaign_detection(domain_name)
    vt = get_virustotal_data(domain_name)
    model_res = get_kendi_risk_skorumuz(domain_name)
    
    # IP'yi model sonucundan al (Çünkü 4 katmanlı çözücü orada çalıştı)
    ip = model_res.get("tespit_edilen_ip")
    abuse = get_abuseipdb_data(ip)

    # 2. OSINT (Shodan & OTX) - IP artık daha güvenilir
    try:
        osint = intel_engine.get_full_intel(domain_name, ip)
    except:
        osint = {}

    # 3. SHAP Grafik
    shap_file = None
    if xai_explainer and "model_input_df" in model_res:
        try:
            shap_file = xai_explainer.generate_shap_waterfall(model_res["model_input_df"], domain_name)
        except: pass

    # 4. Gemini Analizi
    prompt = f"""
    Role: SOC Analyst. Target: {domain_name}
    Data:
    - VT: {vt}
    - AbuseIPDB: {abuse}
    - Risk Score: {model_res.get('risk_skoru_yuzde')}
    - OSINT: {osint}
    
    Task: Write a concise executive summary text (NOT JSON).
    Include: Verdict, Key Evidence (Shodan/VT), Reasoning, and Action.
    """
    
    ai_summary = None
    try:
        if gemini_model:
            ai_summary = gemini_model.generate_content(prompt).text
        else:
            raise Exception("Gemini Off")
    except:
        ai_summary = generate_fallback_summary(domain_name, vt, abuse, model_res)

    # 5. PDF İçin Metin Temizliği (KRİTİK DÜZELTME)
    pdf_text = ""
    if isinstance(ai_summary, dict):
        # Eğer Fallback çalıştıysa sözlük döner, onu metne çeviriyoruz
        pdf_text = ai_summary.get("xai_output", "Analysis Unavailable")
    elif isinstance(ai_summary, str):
        # Eğer Gemini bazen string içinde JSON döndürürse onu yakala
        if ai_summary.strip().startswith("{") and "verdict" in ai_summary:
            try:
                # String görünümlü sözlüğü parse et
                temp_dict = ast.literal_eval(ai_summary)
                pdf_text = temp_dict.get("xai_output", str(temp_dict))
            except:
                pdf_text = ai_summary # Parse edilemezse olduğu gibi bas
        else:
            pdf_text = ai_summary # Zaten düzgün metinse dokunma

    # 6. PDF Oluştur
    try:
        score_val = float(model_res.get('risk_skoru_yuzde', '0').replace('%', ''))
    except: score_val = 0.0
    
    pdf_path = create_pdf_report(
        domain=domain_name,
        ai_summary=pdf_text, # Temizlenmiş metni gönderiyoruz
        risk_score=score_val,
        vt_stats=vt,
        abuse_data=abuse,
        osint_data=osint,
        shap_path=shap_file
    )

    # 7. Yanıt
    response = {
        "domain": domain_name,
        "ai_ozeti": ai_summary, # Slack botu dict/str ayrımını kendi yapıyor
        "ham_veriler": {
            "virustotal": vt,
            "abuseipdb": abuse,
            "kendi_modelimiz": model_res,
            "osint": osint
        },
        "memory_insights": mem,
        "campaign_alert": camp,
        "pdf_report": pdf_path,
        "shap_graph": shap_file
    }
    
    if "model_input_df" in response["ham_veriler"]["kendi_modelimiz"]:
        del response["ham_veriler"]["kendi_modelimiz"]["model_input_df"]
        
    memory_engine.store_analysis(domain_name, response)
    return response

@app.get("/statistics")
def get_stats():
    return {"status": "success", "data": memory_engine.get_statistics()}
