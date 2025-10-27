import os
import joblib  # [YENİ] Modellerin varlığını ve bozuk olup olmadığını test etmek için
import google.generativeai as genai
from dotenv import load_dotenv

print("--- ChatSecOps SOAR Motoru Bağımlılık Kontrolü Başlatıldı ---")

# --- 1. Lokal ML Modeli Kontrolü ---
print("\n[Bölüm 1/2] Lokal Makine Öğrenmesi Modelleri Kontrol Ediliyor...")

# main.py'nin ihtiyaç duyduğu DÜN EĞİTTİĞİMİZ dosyalar
MODEL_FILE = 'lgbm_domain_classifier.joblib'
SCALER_FILE = 'data_scaler.joblib'

model_found = os.path.exists(MODEL_FILE)
scaler_found = os.path.exists(SCALER_FILE)

# Model dosyasını kontrol et
if model_found:
    print(f"✅ [BAŞARILI] Model dosyası bulundu: '{MODEL_FILE}'")
    # Bonus: Modeli yüklemeyi dene (bozuk olup olmadığını anla)
    try:
        joblib.load(MODEL_FILE)
        print("      [+] Model dosyası başarıyla yüklendi (bozuk değil).")
    except Exception as e:
        print(f"      [UYARI] Model dosyası '{MODEL_FILE}' bulundu ancak yüklenemedi (bozuk olabilir): {e}")
else:
    print(f"❌ [HATA] Model dosyası bulunamadı: '{MODEL_FILE}'")

# Scaler dosyasını kontrol et
if scaler_found:
    print(f"✅ [BAŞARILI] Scaler dosyası bulundu: '{SCALER_FILE}'")
    # Bonus: Scaler'ı yüklemeyi dene (bozuk olup olmadığını anla)
    try:
        joblib.load(SCALER_FILE)
        print("      [+] Scaler dosyası başarıyla yüklendi (bozuk değil).")
    except Exception as e:
        print(f"      [UYARI] Scaler dosyası '{SCALER_FILE}' bulundu ancak yüklenemedi (bozuk olabilir): {e}")
else:
    print(f"❌ [HATA] Scaler dosyası bulunamadı: '{SCALER_FILE}'")

# Lokal dosyalar için özet
if not model_found or not scaler_found:
    print("\n[ÖNEMLİ] ML Model dosyalarından biri veya ikisi eksik.")
    print(" 'main.py' uygulaması, kendi risk skorumuzu hesaplarken HATA VERECEKTİR.")
    print(" Lütfen Colab not defterinden `.joblib` dosyalarını bu klasöre indirdiğinizden emin olun.\n")
else:
    print("\n[BAŞARILI] Lokal ML modeli bağımlılıkları tamamlandı.\n")


# --- 2. Harici Gemini API Kontrolü ---
print("---" * 10)
print("[Bölüm 2/2] Harici Gemini API Bağlantısı Kontrol Ediliyor...")

# API anahtarını .env dosyasından yükle
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("❌ [HATA] .env dosyasında GEMINI_API_KEY bulunamadı.")
    print("--- Kontrol Tamamlandı (Hatalarla) ---")
    exit()  # Gemini anahtarı yoksa devam etmenin anlamı yok

try:
    genai.configure(api_key=GEMINI_API_KEY)
    print("✅ [BAŞARILI] Gemini API'sine başarıyla bağlandı. Mevcut modeller listeleniyor...\n")

    # API'ye "Benim hangi modellerim var?" diye sor
    found_model = False
    for model in genai.list_models():
        # Sadece 'generateContent' (bizim ihtiyacımız) metodunu destekleyenleri yazdır
        if 'generateContent' in model.supported_generation_methods:
            print(f"--- Model Adı (Kullanılabilir): ---")
            print(f"   Name: {model.name}")
            print(f"   Description: {model.description}\n")
            found_model = True

    if not found_model:
        print("❌ [HATA] Bu API anahtarı ile 'generateContent' metodunu destekleyen hiçbir model bulunamadı.")
        print("   Lütfen Google AI Studio'da projenizin ve API anahtarınızın doğru yapılandırıldığından emin olun.")
    else:
        print("[BAŞARILI] Gemini API bağımlılıkları tamamlandı.")


except Exception as e:
    print(f"❌ [HATA] Gemini API'sine bağlanırken bir sorun oluştu: {e}")

print("\n--- Bağımlılık Kontrolü Tamamlandı ---")