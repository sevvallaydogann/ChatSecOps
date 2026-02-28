import os
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ALIENVAULT_API_KEY")

print(f"🔑 API Key: {API_KEY[:5]}... (Mevcut mu: {bool(API_KEY)})")

domain = "google.com"
url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
headers = {"X-OTX-API-KEY": API_KEY}

try:
    print(f"📡 {url} adresine istek atılıyor...")
    response = requests.get(url, headers=headers, timeout=10)
    print(f"📥 Durum Kodu: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        count = data.get("pulse_info", {}).get("count", 0)
        print(f"✅ BAŞARILI! Pulse Sayısı: {count}")
    elif response.status_code == 403:
        print("❌ HATA: API Key geçersiz veya yetkisiz!")
    else:
        print(f"⚠️ HATA: {response.text}")
except Exception as e:
    print(f"❌ BAĞLANTI HATASI: {e}")