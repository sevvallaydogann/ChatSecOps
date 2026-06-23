import os
from dotenv import load_dotenv
import requests

# For colored outputs
class Colors:
    OK = '\033[92m'
    FAIL = '\033[91m'
    END = '\033[0m'

print("🔍 API CONNECTION TEST STARTING...\n")

# 1. .env CHECK
load_dotenv()
alien_key = os.getenv("ALIENVAULT_API_KEY")
shodan_key = os.getenv("SHODAN_API_KEY")
gemini_key = os.getenv("GEMINI_API_KEY")

print(f"📂 Reading .env File:")
print(f"   - AlienVault Key: {'✅ Loaded' if alien_key else '❌ MISSING'}")
print(f"   - Shodan Key:     {'✅ Loaded' if shodan_key else '❌ MISSING'}")
print(f"   - Gemini Key:     {'✅ Loaded' if gemini_key else '❌ MISSING'}")
print("-" * 30)

# 2. ALIENVAULT TEST
print("\n👽 AlienVault OTX Test:")
if not alien_key:
    print(f"{Colors.FAIL}   [SKIPPED] No key found.{Colors.END}")
else:
    try:
        from OTXv2 import OTXv2
        otx = OTXv2(alien_key)
        # Let's try a simple query (google.com)
        otx.get_indicator_details_by_section('domain', 'google.com', 'general')
        print(f"{Colors.OK}   [SUCCESS] Connection established!{Colors.END}")
    except ImportError:
        print(f"{Colors.FAIL}   [ERROR] 'OTXv2' library is not installed. (pip install OTXv2){Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}   [ERROR] Connection failed: {e}{Colors.END}")

# 3. SHODAN TEST
print("\n🌐 Shodan Test:")
if not shodan_key:
    print(f"{Colors.FAIL}   [SKIPPED] No key found.{Colors.END}")
else:
    try:
        import shodan
        api = shodan.Shodan(shodan_key)
        # Let's query our own IP
        api.host('8.8.8.8')
        print(f"{Colors.OK}   [SUCCESS] Connection established!{Colors.END}")
    except ImportError:
        print(f"{Colors.FAIL}   [ERROR] 'shodan' library is not installed. (pip install shodan){Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}   [ERROR] Connection failed: {e}{Colors.END}")

# 4. GEMINI TEST
print("\n🤖 Gemini AI Test:")
if not gemini_key:
    print(f"{Colors.FAIL}   [SKIPPED] No key found.{Colors.END}")
else:
    try:
        import google.generativeai as genai
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('models/gemini-2.5-pro') # Or 'gemini-pro'
        response = model.generate_content("Hello")
        print(f"{Colors.OK}   [SUCCESS] Response received: {response.text.strip()}{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}   [ERROR] Gemini Error: {e}{Colors.END}")

print("\n" + "="*30)
print("TEST COMPLETED")