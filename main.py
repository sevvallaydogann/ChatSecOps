# --- 1. GEREKLİ KÜTÜPHANELERİ İÇERİ AKTARMA ---
import os
import requests
import joblib
import pandas as pd
import ipinfo
import socket
import re
from math import log2
from collections import Counter
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
import google.generativeai as genai

try:
    from xai_explainer import ModelExplainer
except Exception as e:
    print(f"❌ [HATA] XAI Explainer sınıfı içe aktarılamadı: {e}")
    ModelExplainer = None

# [YENİ] Gerekli Kütüphaneler (pip install python-whois dnspython GEREKİR)
try:
    import whois
    import dns.resolver
    print("[BİLGİ] 'whois' ve 'dnspython' kütüphaneleri başarıyla yüklendi.")
except ImportError:
    print("❌ [HATA] Gerekli kütüphaneler eksik. Lütfen 'pip install python-whois dnspython' komutunu çalıştırın.")
    whois = None
    dns = None

import time

# --- [VERİ SETİNDEN ALINAN BİLGİLER - DOLDURULDU] ---

# [YENİ] Ölçeklendirilecek 18 adet sayısal sütun (Colab'den alındı)
COLUMNS_TO_SCALE = [
    'ConsoantRatio', 'NumericRatio', 'SpecialCharRatio', 'VowelRatio',
    'Ip', 'CreationDate', 'LastUpdateDate', 'ASN', 'HttpResponseCode',
    'SubdomainNumber', 'Entropy', 'EntropyOfSubDomains', 'StrangeCharacters',
    'ConsoantSequence', 'VowelSequence', 'NumericSequence', 'SpecialCharSequence',
    'DomainLength'
]

# [YENİ] Modelin eğitildiği 284 sütunun tam listesi (Colab'den alındı)
TRAINING_COLUMNS = [
    'MXDnsResponse', 'TXTDnsResponse', 'HasSPFInfo', 'HasDkimInfo', 'HasDmarcInfo', 'Ip', 'DomainInAlexaDB', 'CommonPorts', 'CreationDate', 'LastUpdateDate', 'ASN', 'HttpResponseCode', 'SubdomainNumber', 'Entropy', 'EntropyOfSubDomains', 'StrangeCharacters', 'IpReputation', 'DomainReputation', 'ConsoantRatio', 'NumericRatio', 'SpecialCharRatio', 'VowelRatio', 'ConsoantSequence', 'VowelSequence', 'NumericSequence', 'SpecialCharSequence', 'DomainLength', 'DNSRecordType_A', 'DNSRecordType_CNAME', 'DNSRecordType_MX', 'CountryCode_AD', 'CountryCode_AE', 'CountryCode_AL', 'CountryCode_AR', 'CountryCode_AT', 'CountryCode_AU', 'CountryCode_BA', 'CountryCode_BD', 'CountryCode_BE', 'CountryCode_BG', 'CountryCode_BO', 'CountryCode_BR', 'CountryCode_BS', 'CountryCode_BY', 'CountryCode_Bilinmiyor', 'CountryCode_CA', 'CountryCode_CH', 'CountryCode_CI', 'CountryCode_CL', 'CountryCode_CM', 'CountryCode_CN', 'CountryCode_CO', 'CountryCode_CR', 'CountryCode_CU', 'CountryCode_CW', 'CountryCode_CY', 'CountryCode_CZ', 'CountryCode_DE', 'CountryCode_DK', 'CountryCode_DO', 'CountryCode_DZ', 'CountryCode_EC', 'CountryCode_EE', 'CountryCode_EG', 'CountryCode_ES', 'CountryCode_FI', 'CountryCode_FR', 'CountryCode_GB', 'CountryCode_GE', 'CountryCode_GH', 'CountryCode_GR', 'CountryCode_GT', 'CountryCode_HK', 'CountryCode_HR', 'CountryCode_HU', 'CountryCode_ID', 'CountryCode_IE', 'CountryCode_IL', 'CountryCode_IN', 'CountryCode_IR', 'CountryCode_IS', 'CountryCode_IT', 'CountryCode_JP', 'CountryCode_KE', 'CountryCode_KG', 'CountryCode_KR', 'CountryCode_KY', 'CountryCode_KZ', 'CountryCode_LA', 'CountryCode_LK', 'CountryCode_LT', 'CountryCode_LU', 'CountryCode_LV', 'CountryCode_MA', 'CountryCode_MD', 'CountryCode_MK', 'CountryCode_MN', 'CountryCode_MX', 'CountryCode_MY', 'CountryCode_NC', 'CountryCode_NG', 'CountryCode_NL', 'CountryCode_NO', 'CountryCode_NP', 'CountryCode_NZ', 'CountryCode_OM', 'CountryCode_PA', 'CountryCode_PE', 'CountryCode_PG', 'CountryCode_PH', 'CountryCode_PK', 'CountryCode_PL', 'CountryCode_PS', 'CountryCode_PT', 'CountryCode_PY', 'CountryCode_QA', 'CountryCode_RO', 'CountryCode_RS', 'CountryCode_RU', 'CountryCode_SC', 'CountryCode_SE', 'CountryCode_SG', 'CountryCode_SI', 'CountryCode_SK', 'CountryCode_SN', 'CountryCode_SY', 'CountryCode_TH', 'CountryCode_TN', 'CountryCode_TR', 'CountryCode_TW', 'CountryCode_UA', 'CountryCode_UG', 'CountryCode_US', 'CountryCode_UZ', 'CountryCode_VE', 'CountryCode_VG', 'CountryCode_VN', 'CountryCode_ZA', 'CountryCode_ZW', 'RegisteredCountry_AD', 'RegisteredCountry_AE', 'RegisteredCountry_AL', 'RegisteredCountry_AT', 'RegisteredCountry_AU', 'RegisteredCountry_BA', 'RegisteredCountry_BD', 'RegisteredCountry_BE', 'RegisteredCountry_BG', 'RegisteredCountry_BR', 'RegisteredCountry_BY', 'RegisteredCountry_BZ', 'RegisteredCountry_Bilinmiyor', 'RegisteredCountry_CA', 'RegisteredCountry_CH', 'RegisteredCountry_CI', 'RegisteredCountry_CM', 'RegisteredCountry_CN', 'RegisteredCountry_CR', 'RegisteredCountry_CY', 'RegisteredCountry_CZ', 'RegisteredCountry_DE', 'RegisteredCountry_DK', 'RegisteredCountry_DZ', 'RegisteredCountry_EE', 'RegisteredCountry_EG', 'RegisteredCountry_ES', 'RegisteredCountry_EU', 'RegisteredCountry_Es', 'RegisteredCountry_FI', 'RegisteredCountry_FR', 'RegisteredCountry_GB', 'RegisteredCountry_GE', 'RegisteredCountry_GI', 'RegisteredCountry_GR', 'RegisteredCountry_HK', 'RegisteredCountry_HR', 'RegisteredCountry_HU', 'RegisteredCountry_ID', 'RegisteredCountry_IE', 'RegisteredCountry_IL', 'RegisteredCountry_IM', 'RegisteredCountry_IN', 'RegisteredCountry_IR', 'RegisteredCountry_IS', 'RegisteredCountry_IT', 'RegisteredCountry_JP', 'RegisteredCountry_KE', 'RegisteredCountry_KG', 'RegisteredCountry_KR', 'RegisteredCountry_KY', 'RegisteredCountry_KZ', 'RegisteredCountry_LI', 'RegisteredCountry_LK', 'RegisteredCountry_LT', 'RegisteredCountry_LU', 'RegisteredCountry_LV', 'RegisteredCountry_MA', 'RegisteredCountry_MD', 'RegisteredCountry_MK', 'RegisteredCountry_MN', 'RegisteredCountry_MR', 'RegisteredCountry_MU', 'RegisteredCountry_MY', 'RegisteredCountry_NC', 'RegisteredCountry_NG', 'RegisteredCountry_NL', 'RegisteredCountry_NO', 'RegisteredCountry_NP', 'RegisteredCountry_NZ', 'RegisteredCountry_OM', 'RegisteredCountry_PG', 'RegisteredCountry_PH', 'RegisteredCountry_PK', 'RegisteredCountry_PL', 'RegisteredCountry_PS', 'RegisteredCountry_PT', 'RegisteredCountry_QA', 'RegisteredCountry_RO', 'RegisteredCountry_RS', 'RegisteredCountry_RU', 'RegisteredCountry_Ro', 'RegisteredCountry_SA', 'RegisteredCountry_SC', 'RegisteredCountry_SE', 'RegisteredCountry_SG', 'RegisteredCountry_SI', 'RegisteredCountry_SK', 'RegisteredCountry_SM', 'RegisteredCountry_SN', 'RegisteredCountry_SY', 'RegisteredCountry_TH', 'RegisteredCountry_TN', 'RegisteredCountry_TR', 'RegisteredCountry_TW', 'RegisteredCountry_UA', 'RegisteredCountry_UG', 'RegisteredCountry_US', 'RegisteredCountry_UZ', 'RegisteredCountry_VN', 'RegisteredCountry_YU', 'RegisteredCountry_ZA', 'RegisteredCountry_ZW', 'RegisteredCountry_de', 'RegisteredCountry_dk', 'RegisteredCountry_es', 'RegisteredCountry_fr', 'RegisteredCountry_md', 'RegisteredCountry_ro', 'RegisteredCountry_ru', 'RegisteredCountry_tr', 'RegisteredCountry_ua', 'RegisteredCountry_us', 'RegisteredCountry_vn', 'TLD_Grouped_TLD_Other', 'TLD_Grouped_bid', 'TLD_Grouped_biz', 'TLD_Grouped_blogspot.com', 'TLD_Grouped_ca', 'TLD_Grouped_cl', 'TLD_Grouped_cn', 'TLD_Grouped_co.uk', 'TLD_Grouped_co.za', 'TLD_Grouped_com', 'TLD_Grouped_com.au', 'TLD_Grouped_com.br', 'TLD_Grouped_cz', 'TLD_Grouped_de', 'TLD_Grouped_es', 'TLD_Grouped_eu', 'TLD_Grouped_fr', 'TLD_Grouped_in', 'TLD_Grouped_info', 'TLD_Grouped_it', 'TLD_Grouped_net', 'TLD_Grouped_nl', 'TLD_Grouped_online', 'TLD_Grouped_org', 'TLD_Grouped_pl', 'TLD_Grouped_ro', 'TLD_Grouped_ru', 'TLD_Grouped_sx.cn', 'TLD_Grouped_top', 'TLD_Grouped_us', 'TLD_Grouped_xyz'
]

# [YENİ] TLD Gruplaması için Top 30 listesi (Colab'den alındı)
TOP_30_TLDS = [
    'com', 'net', 'online', 'com.br', 'org', 'ru', 'sx.cn', 'top', 'blogspot.com', 'info', 'co.uk', 'pl', 'com.au', 'de', 'cn', 'bid', 'it', 'in', 'fr', 'xyz', 'nl', 'es', 'cl', 'ro', 'eu', 'ca', 'us', 'biz', 'cz', 'co.za'
]


# --- 2. KURULUM VE BAŞLANGIÇ AYARLARI ---

print("[BİLGİ] SOAR Motoru başlatılıyor...")
load_dotenv()
print("[BİLGİ] .env dosyası yüklendi.")

# API anahtarlarını .env dosyasından değişkenlere ata
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

app = FastAPI(title="ChatSecOps SOAR Motoru")

# ML Modelimizi (LGBM) ve Scaler'ı diskten yükle
try:
    model = joblib.load('lgbm_domain_classifier.joblib')
    scaler = joblib.load('data_scaler.joblib')
    print("✅ [BAŞARILI] ML Modeli (LightGBM) ve Scaler (data_scaler.joblib) başarıyla yüklendi.")
except FileNotFoundError:
    print("❌ [HATA] 'lgbm_domain_classifier.joblib' veya 'data_scaler.joblib' bulunamadı.")
    model, scaler = None, None
except Exception as e:
    print(f"❌ [HATA] Model yüklenirken beklenmedik hata: {e}")
    model, scaler = None, None

# Gemini AI modelini kur ve yapılandır
try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('models/gemini-2.5-pro')
    # --- DÜZELTİLMİŞ PRINT SATIRI ---
    print(" BAŞARILI Gemini AI Modeli (models/gemini-2.5-pro) yüklendi.")
except Exception as e:
    print(f"❌ [HATA] Gemini modeli yüklenemedi: {e}")
    gemini_model = None

# XAI açıklama motorunu yükle
if ModelExplainer:
    try:
        xai_explainer = ModelExplainer('lgbm_domain_classifier.joblib')
        print("✅ [BAŞARILI] XAI Explainer yüklendi.")
    except Exception as e:
        print(f"❌ [HATA] XAI Explainer yüklenemedi: {e}")
        xai_explainer = None
else:
    xai_explainer = None

# IP'den bilgi bulan (ipinfo) servisini kur
try:
    ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN)
    print("✅ [BAŞARILI] IPinfo servisi (ülke/ASN bulucu) yüklendi.")
except Exception as e:
    print(f"❌ [HATA] IPinfo servisi yüklenemedi: {e}")
    ipinfo_handler = None


# --- 3. YARDIMCI FONKSİYONLAR (PLAYBOOK'LAR) ---

# --- Playbook 1: Harici API'ler ---
def get_virustotal_data(domain: str):
    print(f"      [>] VirusTotal (Domain) sorgulanıyor: {domain}")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {}).get("attributes", {})
        return data.get("last_analysis_stats", {"hata": "Veri bulunamadı"})
    except requests.exceptions.RequestException as e:
        print(f"      ❌ [HATA] VirusTotal bağlantı hatası: {e}")
        return {"hata": str(e)}

def get_abuseipdb_data(ip: str):
    print(f"      [>] AbuseIPDB (IP) sorgulanıyor: {ip}")
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})
        return {"abuseConfidenceScore": data.get("abuseConfidenceScore"), "totalReports": data.get("totalReports")}
    except requests.exceptions.RequestException as e:
        print(f"      ❌ [HATA] AbuseIPDB bağlantı hatası: {e}")
        return {"hata": str(e)}

# --- Playbook 2: Kendi ML Modelimiz için Canlı Özellik Toplama ---

def get_ip_from_domain(domain: str) -> str | None:
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"      [>] DNS Çözümlemesi: {domain} -> {ip_address}")
        return ip_address
    except socket.error as e:
        print(f"      ❌ [HATA] Domain'den IP çözümlenemedi: {e}")
        return None

def get_network_features(ip: str) -> dict:
    if not ipinfo_handler:
        return {"CountryCode": "Bilinmiyor", "ASN": -1, "hata": "IPinfo servisi yüklenemedi"}
    try:
        details = ipinfo_handler.getDetails(ip)
        asn_str = getattr(details, 'asn', '-1').replace('AS', '')
        asn = int(asn_str) if asn_str.isdigit() else -1
        return {
            "CountryCode": getattr(details, 'country', 'Bilinmiyor'),
            "ASN": asn
        }
    except Exception as e:
        print(f"      ❌ [HATA] IPinfo sorgusunda hata: {e}")
        return {"CountryCode": "Bilinmiyor", "ASN": -1, "hata": str(e)}

def calculate_shannon_entropy(data: str) -> float:
    if not data: return 0.0
    entropy = 0; str_len = len(data); counts = Counter(data)
    for char_count in counts.values():
        p_x = char_count / str_len; entropy -= p_x * log2(p_x)
    return entropy

def get_dns_features(domain: str) -> dict:
    if not dns:
        return {'DNSRecordType': 'Bilinmiyor', 'MXDnsResponse': False, 'TXTDnsResponse': False, 'HasSPFInfo': False}

    features = {
        'DNSRecordType': 'Bilinmiyor', 'MXDnsResponse': False,
        'TXTDnsResponse': False, 'HasSPFInfo': False
    }
    resolver = dns.resolver.Resolver(); resolver.timeout = 2; resolver.lifetime = 2

    try:
        answer = resolver.resolve(domain, 'A'); features['DNSRecordType'] = 'A'
    except (dns.resolver.NoAnswer, dns.exception.Timeout):
        try:
            answer = resolver.resolve(domain, 'CNAME'); features['DNSRecordType'] = 'CNAME'
        except Exception: pass
    except Exception: pass

    try:
        resolver.resolve(domain, 'MX'); features['MXDnsResponse'] = True
    except Exception: pass

    try:
        txt_records = resolver.resolve(domain, 'TXT')
        features['TXTDnsResponse'] = True
        for record in txt_records:
            if 'v=spf1' in str(record).lower():
                features['HasSPFInfo'] = True; break
    except Exception: pass

    print(f"      [>] DNS Özellikleri: {features}")
    return features

def get_whois_features(domain: str) -> dict:
    if not whois:
        return {"CreationDate": -1, "LastUpdateDate": -1, "RegisteredCountry": "Bilinmiyor"}

    features = {"CreationDate": -1, "LastUpdateDate": -1, "RegisteredCountry": "Bilinmiyor"}
    try:
        w = whois.whois(domain) # type: ignore
        if w:
            creation_date = w.creation_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if creation_date:
                features['CreationDate'] = int(creation_date.timestamp())

            last_updated = w.last_updated
            if isinstance(last_updated, list): last_updated = last_updated[0]
            if last_updated:
                features['LastUpdateDate'] = int(last_updated.timestamp())

            country = w.registrant_country
            if country:
                features['RegisteredCountry'] = country.strip()

    except Exception as e:
        print(f"      [UYARI] Whois sorgusu '{domain}' için başarısız: {e}")
        pass

    print(f"      [>] Whois Özellikleri: {features}")
    return features

def get_live_features_for_model(domain: str) -> (dict, str | None):

    # 1. Ağ Özellikleri
    ip_address = get_ip_from_domain(domain)
    ip_int = -1
    if ip_address:
        network_features = get_network_features(ip_address)
        try:
            ip_int = int(''.join([f"{int(x):08b}" for x in ip_address.split('.')]), 2)
        except: ip_int = -1
    else:
        network_features = {"CountryCode": "Bilinmiyor", "ASN": -1}

    # 2. DNS Özellikleri
    dns_features = get_dns_features(domain)

    # 3. WHOIS Özellikleri
    whois_features = get_whois_features(domain)

    # 4. Leksik Özellikler
    domain_len = len(domain)
    numerics = re.findall(r"[0-9]", domain)
    vowels = re.findall(r"[aeiouAEIOU]", domain)
    consonants = re.findall(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]", domain)
    special_chars = re.findall(r"[^a-zA-Z0-9.\-]", domain)

    parts = domain.split('.')
    tld_original = parts[-1] if len(parts) > 1 else "Bilinmiyor"
    tld_grouped = tld_original if tld_original in TOP_30_TLDS else 'TLD_Other'

    live_feature_dict = {
        # Leksik
        'DomainLength': domain_len,
        'Entropy': calculate_shannon_entropy(domain),
        'NumericRatio': len(numerics) / domain_len if domain_len > 0 else 0,
        'VowelRatio': len(vowels) / domain_len if domain_len > 0 else 0,
        'ConsoantRatio': len(consonants) / domain_len if domain_len > 0 else 0,
        'SpecialCharRatio': len(special_chars) / domain_len if domain_len > 0 else 0,
        'TLD_Grouped': tld_grouped, # 'TLD'ye gerek yok, OHE'yi TLD_Grouped'dan yapacağız

        # Ağ
        'Ip': ip_int,
        'CountryCode': network_features['CountryCode'],
        'ASN': network_features['ASN'],

        # DNS
        'DNSRecordType': dns_features['DNSRecordType'],
        'MXDnsResponse': dns_features['MXDnsResponse'],
        'TXTDnsResponse': dns_features['TXTDnsResponse'],
        'HasSPFInfo': dns_features['HasSPFInfo'],

        # WHOIS
        'RegisteredCountry': whois_features['RegisteredCountry'],
        'CreationDate': whois_features['CreationDate'],
        'LastUpdateDate': whois_features['LastUpdateDate'],

        # Dataset'teki diğer özellikler için varsayılanlar
        # (Bunların birçoğu '0' veya 'False' idi)
        'StrangeCharacters': 0, 'SubdomainNumber': domain.count('.'),
        'EntropyOfSubDomains': 0, 'ConsoantSequence': 0,
        'VowelSequence': 0, 'NumericSequence': 0, 'SpecialCharSequence': 0,
        'HttpResponseCode': -1, 'DomainInAlexaDB': False,
        'CommonPorts': False, 'HasDkimInfo': False, 'HasDmarcInfo': False,
        'IpReputation': 0, 'DomainReputation': 0 # Bunları canlıda almadığımız için 0 varsayıyoruz
    }

    return live_feature_dict, ip_address


def get_kendi_risk_skorumuz(domain: str) -> dict:
    print(f"      [>] Kendi ML Modelimiz (LightGBM %99.75) sorgulanıyor...")

    if not model or not scaler:
        return {"hata": "ML Modeli (LGBM) veya Scaler (data_scaler) yüklenemedi."}

    if not TRAINING_COLUMNS or len(TRAINING_COLUMNS) != 284:
         return {"hata": f"KRİTİK HATA: 'TRAINING_COLUMNS' listesi 284 sütun olmalı! Mevcut: {len(TRAINING_COLUMNS)}"}

    if not TOP_30_TLDS or len(TOP_30_TLDS) != 30:
         return {"hata": f"KRİTİK HATA: 'TOP_30_TLDS' listesi 30 TLD olmalı! Mevcut: {len(TOP_30_TLDS)}"}

    try:
        # 1. Adım: Canlı özellikleri topla
        live_feature_dict, ip_address = get_live_features_for_model(domain)

        # 2. Adım: Modele uygun DataFrame'i hazırla
        input_df_raw = pd.DataFrame([live_feature_dict])

        # Kategorik sütunlara OHE uygula
        ohe_columns = ['DNSRecordType', 'CountryCode', 'RegisteredCountry', 'TLD_Grouped']
        input_df_ohe = pd.get_dummies(input_df_raw, columns=ohe_columns, dtype=int)

        # 3. Adım: Eğitim Sütunları ile Hizalama
        final_input_df = pd.DataFrame(columns=TRAINING_COLUMNS)
        final_input_df = input_df_ohe.reindex(columns=TRAINING_COLUMNS, fill_value=0)

        # 4. Adım: Veriyi Ölçeklendir (Scaler)
        final_input_df[COLUMNS_TO_SCALE] = scaler.transform(final_input_df[COLUMNS_TO_SCALE])

        print("      [>] Model için 284 sütunluk canlı veri hazırlandı ve ölçeklendirildi.")

        # 5. Adım: Modele tahminde bulundur
        final_input_df.columns = [re.sub(r'[^A-Za-z0-9_]+', '', col) for col in final_input_df.columns]

        probability = model.predict_proba(final_input_df)[0]
        prediction = model.predict(final_input_df)[0]
        risk_score_percent = probability[1] * 100

        # === XAI KISMI - GÜNCELLEME ===
        explanation_data = None
        
        if xai_explainer is not None:
            try:
                print("      [>] XAI (SHAP) açıklaması oluşturuluyor...")
                
                # XAI explainer'dan açıklama al
                raw_explanation = xai_explainer.generate_explanation(final_input_df.copy())
                
                # DEBUG
                print(f"      [DEBUG] XAI ham veri keys: {raw_explanation.keys() if isinstance(raw_explanation, dict) else 'Not a dict'}")
                
                # Mevcut xai_explainer.py formatı: 'top_5_positive_features' ve 'top_5_negative_features'
                if isinstance(raw_explanation, dict):
                    pos_features = raw_explanation.get('top_5_positive_features', [])
                    neg_features = raw_explanation.get('top_5_negative_features', [])
                    
                    print(f"      [DEBUG] Pozitif features: {len(pos_features)}, Negatif features: {len(neg_features)}")
                    
                    # İki listeyi birleştir ve standart formata dönüştür
                    combined_features = []
                    
                    # Pozitif features ekle
                    for feat in pos_features:
                        combined_features.append({
                            'feature': feat['feature'],
                            'shap_value': feat['shap_value'],
                            'impact': 'positive'
                        })
                    
                    # Negatif features ekle
                    for feat in neg_features:
                        combined_features.append({
                            'feature': feat['feature'],
                            'shap_value': feat['shap_value'],
                            'impact': 'negative'
                        })
                    
                    # Standart format oluştur
                    explanation_data = {
                        'top_features': combined_features,
                        'explanation_method': 'SHAP TreeExplainer',
                        'total_features': len(combined_features)
                    }
                    
                    print(f"      [✅] XAI açıklaması başarıyla alındı ({len(combined_features)} features).")
                else:
                    print(f"      [⚠️] XAI beklenmedik format: {type(raw_explanation)}")
                    explanation_data = None
                    
            except Exception as e:
                print(f"      ❌ [HATA] XAI açıklaması oluşturulamadı: {e}")
                import traceback
                traceback.print_exc()
                explanation_data = None
        else:
            print("      [⚠️] XAI Explainer yüklenmedi, açıklama atlanıyor.")

        # === RESPONSE OLUŞTUR ===
        response = {
            "tahmin_sinifi": int(prediction),
            "risk_skoru_yuzde": f"{risk_score_percent:.2f}%",
            "tespit_edilen_ip": ip_address,
            "tespit_edilen_ulke": live_feature_dict.get('CountryCode'),
            "model_yorumu": "Bu skor, 90K'lık dataset ile eğitilmiş LightGBM (%99.75) modelimize aittir."
        }

        # XAI verisi varsa ekle
        if explanation_data is not None and explanation_data:
            response["xai_aciklama"] = explanation_data
        else:
            response["xai_aciklama"] = {
                "hata": "XAI verileri oluşturulamadı",
                "top_features": []
            }

        return response

    except Exception as e:
        print(f"      ❌ [HATA] Kendi ML Modelimizde hata: {e}")
        import traceback
        traceback.print_exc()
        return {"hata": str(e)}

    except Exception as e:
        print(f"      ❌ [HATA] Kendi ML Modelimizde hata: {e}")
        import traceback; traceback.print_exc()
        return {"hata": str(e)}

def generate_fallback_summary(domain_name: str, vt_data: dict, abuse_data: dict, kendi_model_skoru: dict) -> str:
    """
    Gemini hata verdiğinde otomatik olarak kullanılacak yedek rapor.
    ML + XAI sonuçlarını yapılandırılmış formatta sunar.
    """
    
    # Risk skorunu çıkar
    risk_score = kendi_model_skoru.get("risk_skoru_yuzde", "N/A")
    try:
        risk_num = float(risk_score.replace("%", ""))
        if risk_num >= 80:
            risk_level = "KRİTİK"
            action = "ENGELLEME"
        elif risk_num >= 50:
            risk_level = "YÜKSEK"
            action = "İZLEME"
        elif risk_num >= 20:
            risk_level = "ORTA"
            action = "İZLEME"
        else:
            risk_level = "DÜŞÜK"
            action = "GÜVENLİ"
    except:
        risk_level = "BİLİNMİYOR"
        action = "MANUEL İNCELEME"
    
    # VirusTotal sonuçları
    vt_status = "N/A"
    if "hata" not in vt_data:
        vt_malicious = vt_data.get("malicious", 0)
        vt_total = sum(vt_data.values())
        vt_status = f"{vt_malicious}/{vt_total}"
    
    # AbuseIPDB sonuçları
    abuse_status = "N/A"
    if "hata" not in abuse_data:
        abuse_score = abuse_data.get("abuseConfidenceScore", 0)
        abuse_status = f"{abuse_score}%"
    
    # XAI Analizi
    xai_summary = "XAI verileri mevcut değil."
    xai_data = kendi_model_skoru.get("xai_aciklama", {})
    
    if xai_data and "hata" not in xai_data:
        top_features = xai_data.get("top_features", [])
        
        if top_features and len(top_features) > 0:
            # Pozitif (risk artıran) ve negatif (risk azaltan) features'ları ayır
            positive_features = [f for f in top_features if f.get('impact') == 'positive']
            negative_features = [f for f in top_features if f.get('impact') == 'negative']
            
            xai_summary = "Modelin karar gerekçesi (SHAP analizi):\n\n"
            
            # Pozitif features (risk artıran)
            if positive_features:
                xai_summary += "📈 Risk Skorunu ARTIRAN Özellikler:\n"
                for i, feat in enumerate(positive_features[:3], 1):
                    feat_name = feat.get('feature', 'N/A')
                    shap_val = feat.get('shap_value', 0)
                    xai_summary += f"  {i}. {feat_name} (SHAP: +{shap_val:.4f})\n"
                xai_summary += "\n"
            
            # Negatif features (risk azaltan)
            if negative_features:
                xai_summary += "📉 Risk Skorunu AZALTAN Özellikler:\n"
                for i, feat in enumerate(negative_features[:3], 1):
                    feat_name = feat.get('feature', 'N/A')
                    shap_val = feat.get('shap_value', 0)
                    xai_summary += f"  {i}. {feat_name} (SHAP: {shap_val:.4f})\n"
            
            if not positive_features and not negative_features:
                xai_summary = "XAI verileri mevcut ama feature'lar ayrıştırılamadı."
        else:
            xai_summary = "XAI verileri mevcut ama top features bulunamadı."
    else:
        error_msg = xai_data.get("hata", "Bilinmeyen hata") if xai_data else "Veri yok"
        xai_summary = f"XAI verileri oluşturulamadı: {error_msg}"
    
    # Yedek rapor oluştur
    fallback_report = f"""
⚠️ [LLM GEÇİCİ OLARAK KULLANILAMADI - OTOMATIK RAPOR]

=== TI / ML KARAR ÖZETİ ===

Domain: {domain_name}

Harici Kaynaklar:
• VirusTotal: {vt_status} zararlı tespit
• AbuseIPDB: Güven Skoru {abuse_status}

Kendi ML Modelimiz (LightGBM %99.75):
• Risk Skoru: {risk_score}
• Risk Seviyesi: {risk_level}
• Tespit Edilen IP: {kendi_model_skoru.get('tespit_edilen_ip', 'N/A')}
• Ülke: {kendi_model_skoru.get('tespit_edilen_ulke', 'N/A')}

=== XAI ANALİZİ ===

{xai_summary}

=== RİSK SINIFLANDIRMASI ===

{risk_level}

=== EYLEM ÖNERİSİ ===

{action}

---
ℹ️ Bu rapor, LLM servisi kullanılamadığında otomatik olarak üretilmiştir.
   Tüm teknik veriler (TI, ML, XAI) yukarıda sunulmuştur.
"""
    
    return fallback_report


# Şimdi enrich_and_summarize_domain fonksiyonunu güncelleyin:

@app.get("/enrich-and-summarize/domain/{domain_name}")
def enrich_and_summarize_domain(domain_name: str):
    print(f"\n[!] YENİ İSTEK ALINDI: DOMAIN = {domain_name}")

    # TI ve ML verilerini topla
    vt_data = get_virustotal_data(domain_name)
    kendi_model_skoru = get_kendi_risk_skorumuz(domain_name)

    ip_for_abuse = kendi_model_skoru.get("tespit_edilen_ip")
    if ip_for_abuse:
        abuse_data = get_abuseipdb_data(ip_for_abuse)
    else:
        abuse_data = {"hata": "Domain'e ait IP bulunamadığı için sorgulanamadı."}

    # Gemini prompt (aynı kalıyor)
    prompt_template = f"""
Sen, bir siber güvenlik operasyon merkezinde (SOC) görevli **Kıdemli Tehdit İstihbaratı (TI) Analistisin**.

Görevin, {domain_name} alan adı hakkında toplanan tüm bilgileri (Harici API'lar, Kendi ML Modelimiz ve XAI Verisi) füzyon yaparak analiz etmek ve eyleme geçirilebilir bir rapor hazırlamaktır.

--- GİRİŞ VERİLERİ (JSON FORMATINDA) ---

Harici API Verileri:
1. VirusTotal (Domain): {vt_data}
2. AbuseIPDB (IP): {abuse_data}

Kendi ML Modelimiz (LightGBM %99.75):
{kendi_model_skoru}

--- ANALİZ GEREKSİNİMLERİ ---

Sadece tek bir analiz raporu çıktısı vermelisin. Bu rapor, aşağıdaki 4 temel bölümü içermelidir:

1.  **TI / ML Karar Özeti:**
    * VirusTotal, AbuseIPDB ve Kendi ML Modelimizin ({kendi_model_skoru.get('risk_skoru_yuzde', 'N/A')}) sonuçlarını tek bir paragrafta birleştir.
    * **Ana Odak:** Karar verme sürecindeki belirsizlikleri (Örn: AbuseIPDB'de skor 0 iken ML'in yüksek skor vermesi gibi) netleştir.

2.  **Modelin Karar Gerekçesi (XAI Analizi):**
    * 'xai_aciklama' altındaki verileri kullanarak, ML modelinin neden bu risk skoruna ulaştığını açıkla.
    * **Zararlıya İten (Pozitif) Özellikler:** Modelin risk skorunu en çok artıran ilk 3 özellik (Örn: TLD_Grouped_xyz, ASN, Entropy) ve bu özelliklerin değerleri nelerdir?
    * **Güvenliye İten (Negatif) Özellikler:** Modelin zararsız olduğuna en çok ikna eden (skoru düşüren) ilk 3 özellik nelerdir?

3.  **Risk Sınıflandırması:**
    * Tüm verileri dikkate alarak net bir **Risk Seviyesi** belirle. (Sadece şu terimlerden birini kullan: DÜŞÜK, ORTA, YÜKSEK, KRİTİK).

4.  **Eylem Önerisi (SOAR Kararı):**
    * SOC operatörünün hemen uygulayabileceği net bir aksiyon sun. (Sadece şu terimlerden birini kullan: ENGELLEME, İZLEME, GÜVENLİ).

--- RAPOR FORMATI ---

Cevabını doğrudan rapor içeriğiyle başlat. Başlık ve alt başlıklar kullanma. Tüm bilgiyi, analizin mantıksal akışını takip eden tek bir metin bloğu olarak sun.
"""

    print(f"      [>] Gemini AI sorgulanıyor...")

    # Gemini çağrısı - HATA YÖNETİMİ İLE
    ai_summary = None
    gemini_error = None
    
    try:
        if not gemini_model:
            raise Exception("Gemini modeli başlangıçta yüklenemedi.")
        
        response = gemini_model.generate_content(prompt_template)
        ai_summary = response.text.strip()
        print(f"      [✅] Gemini AI yanıtı alındı.")
    
    except Exception as e:
        gemini_error = str(e)
        print(f"      [⚠️] Gemini AI hatası: {e}")
        print(f"      [>] Yedek rapor oluşturuluyor...")
        
        # YEDEK RAPOR OLUŞTUR
        ai_summary = generate_fallback_summary(domain_name, vt_data, abuse_data, kendi_model_skoru)
        print(f"      [✅] Yedek rapor başarıyla oluşturuldu.")

    # Yanıtı döndür
    response_data = {
        "domain": domain_name,
        "ai_ozeti": ai_summary,
        "ham_veriler": {
            "virustotal": vt_data,
            "abuseipdb": abuse_data,
            "kendi_modelimiz": kendi_model_skoru
        }
    }
    
    # Eğer Gemini hata verdiyse bunu belirt
    if gemini_error:
        response_data["llm_status"] = "fallback"
        response_data["llm_error"] = gemini_error
    else:
        response_data["llm_status"] = "success"
    
    return response_data