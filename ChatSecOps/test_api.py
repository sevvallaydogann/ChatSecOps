import os
from dotenv import load_dotenv
import requests

# Renkli çıktılar için
class Colors:
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

print("🔍 API BAĞLANTI TESTİ BAŞLIYOR...\n")

# 1. .env KONTROLÜ
load_dotenv()
alien_key = os.getenv("ALIENVAULT_API_KEY")
shodan_key = os.getenv("SHODAN_API_KEY")
gemini_key = os.getenv("GEMINI_API_KEY")

print(f"📂 .env Dosyası Okunuyor:")
print(f"   - AlienVault Key: {'✅ Yüklü' if alien_key else '❌ EKSİK'}")
print(f"   - Shodan Key:     {'✅ Yüklü' if shodan_key else '❌ EKSİK'}")
print(f"   - Gemini Key:     {'✅ Yüklü' if gemini_key else '❌ EKSİK'}")
print("-" * 30)

# 2. ALIENVAULT TESTİ
print("\n👽 AlienVault OTX Testi:")
if not alien_key:
    print(f"{Colors.FAIL}   [ATLANDI] Anahtar yok.{Colors.END}")
else:
    try:
        from OTXv2 import OTXv2
        otx = OTXv2(alien_key)
        # Basit bir sorgu deneyelim (google.com)
        otx.get_indicator_details_by_section('domain', 'google.com', 'general')
        print(f"{Colors.OK}   [BAŞARILI] Bağlantı sağlandı!{Colors.END}")
    except ImportError:
        print(f"{Colors.FAIL}   [HATA] 'OTXv2' kütüphanesi yüklü değil. (pip install OTXv2){Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}   [HATA] Bağlantı başarısız: {e}{Colors.END}")

# 3. SHODAN TESTİ
print("\n🌐 Shodan Testi:")
if not shodan_key:
    print(f"{Colors.FAIL}   [ATLANDI] Anahtar yok.{Colors.END}")
else:
    try:
        import shodan
        api = shodan.Shodan(shodan_key)
        # Kendi IP'mizi sorgulayalım
        api.host('8.8.8.8')
        print(f"{Colors.OK}   [BAŞARILI] Bağlantı sağlandı!{Colors.END}")
    except ImportError:
        print(f"{Colors.FAIL}   [HATA] 'shodan' kütüphanesi yüklü değil. (pip install shodan){Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}   [HATA] Bağlantı başarısız: {e}{Colors.END}")

# 4. GEMINI TESTİ
print("\n🤖 Gemini AI Testi:")
if not gemini_key:
    print(f"{Colors.FAIL}   [ATLANDI] Anahtar yok.{Colors.END}")
else:
    try:
        import google.generativeai as genai
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('models/gemini-2.5-pro') # Veya 'gemini-pro'
        response = model.generate_content("Hello")
        print(f"{Colors.OK}   [BAŞARILI] Yanıt alındı: {response.text.strip()}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}   [HATA] Gemini Hatası: {e}{Colors.END}")

print("\n" + "="*30)
print("TEST TAMAMLANDI")