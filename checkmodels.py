import os
import joblib 
import json
import google.generativeai as genai
from dotenv import load_dotenv

print("--- 🛡️ ChatSecOps v2 Bağımlılık Kontrolü Başlatıldı ---")

# --- 1. Lokal ML Modeli ve Metadata Kontrolü ---
print("\n[Bölüm 1/2] Yeni ML Modelleri ve Metadata Kontrol Ediliyor...")

# Notebook'ta (Cell 6) ürettiğimiz güncel dosya isimleri
MODEL_FILE = 'model_outputs/chatsecops_model_v2_20260114_203833.joblib'
SCALER_FILE = 'model_outputs/chatsecops_model_v2_20260114_203833_scaler.joblib'
METADATA_FILE = 'model_outputs/chatsecops_model_v2_20260114_203833_metadata.json'

files_to_check = [MODEL_FILE, SCALER_FILE, METADATA_FILE]
all_ok = True

for file in files_to_check:
    if os.path.exists(file):
        print(f"✅ [BAŞARILI] Dosya bulundu: '{file}'")
        # Dosya bozuk mu kontrol et
        try:
            if file.endswith('.joblib'):
                joblib.load(file)
            elif file.endswith('.json'):
                with open(file, 'r', encoding='utf-8') as f:
                    json.load(f)
            print(f"      [+] '{os.path.basename(file)}' başarıyla okundu (bozuk değil).")
        except Exception as e:
            print(f"      ❌ [HATA] '{file}' bulundu ancak okunamadı: {e}")
            all_ok = False
    else:
        print(f"❌ [HATA] Dosya eksik: '{file}'")
        all_ok = False

if all_ok:
    print("\n🎉 [BAŞARILI] Tüm lokal ML bileşenleri (v2) hazır.\n")
else:
    print("\n⚠️ [ÖNEMLİ] ML bileşenlerinde eksik var! 'main.py' düzgün çalışmayabilir.\n")


# --- 2. Harici Gemini API Kontrolü ---
print("---" * 10)
print("[Bölüm 2/2] Gemini API (models/gemini-2.5-pro) Kontrol Ediliyor...")

load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ [HATA] .env dosyasında GEMINI_API_KEY bulunamadı.")
    exit()

try:
    genai.configure(api_key=GEMINI_API_KEY)
    # Gemini 2.5 Pro modelinin listede olup olmadığını kontrol et
    model_names = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
    
    target_model = "models/gemini-2.5-pro"
    
    if target_model in model_names:
        print(f"✅ [BAŞARILI] {target_model} API anahtarınızla kullanılabilir durumda.")
    else:
        print(f"⚠️ [UYARI] {target_model} listede bulunamadı. Mevcut modeller:")
        for name in model_names: print(f"  - {name}")

except Exception as e:
    print(f"❌ [HATA] Gemini API bağlantı sorunu: {e}")

print("\n--- Bağımlılık Kontrolü Tamamlandı ---")