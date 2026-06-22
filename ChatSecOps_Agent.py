import os
import json
import logging
from typing import Dict, Any

# Gemini v1beta zorlaması (AQ. formatı için kalıyor)
os.environ["GOOGLE_API_USE_V1BETA"] = "true"

import google.generativeai as genai

# Diğer kütüphaneler (Eğer ortamda yoksa pip install openai requests yapabilirsin)
try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# Projenin kendi local modülleri
from ChatSecOps_Intelligence import intel_engine
from ChatSecOps_URLParser import url_parser
from ChatSecOps_MITRE import mitre_mapper
from ChatSecOps_Pivot import pivot_engine

logger = logging.getLogger(__name__)

# System Instruction (Tüm yapay zekalara ortak gönderilecek)
SYSTEM_INSTRUCTION = """
You are the ChatSecOps Autonomous Cyber Security Threat Intelligence Agent.
Your goal is to investigate indicator of compromises (IOCs), domains, and URLs sent by users via Slack.
Synthesize everything into a final English response with clear sections: Verdict, Risk Score, Evidence, and Actions.
Do not truncate mid-sentence.
"""

class MultiLLMRouterAgent:
    def __init__(self):
        # API Anahtarlarını yükle
        self.gemini_key = os.getenv("GEMINI_API_KEY")
        self.openai_key = os.getenv("OPENAI_API_KEY")
        self.groq_key = os.getenv("GROQ_API_KEY")
        
        # Sağlayıcıları yapılandır
        if self.gemini_key:
            genai.configure(api_key=self.gemini_key.strip().replace('"', ''))

    def handle_message(self, user_message: str) -> str:
        """
        Gelen mesajı sırayla yapay zeka havuzundaki modellere gönderir.
        Hangisinin kotası canlıysa analizi o yapar!
        """
        # 1. STRATEJİ: HER ZAMAN İLK OLARAK GEMINI DENE
        if self.gemini_key:
            try:
                logger.info("[ROUTER] Attempting investigation with Gemini (Primary)...")
                # İstek anında modeli çağırarak başlangıçtaki kilitlenmeyi engelliyoruz
                model = genai.GenerativeModel(
                    model_name='models/gemini-1.5-flash',
                    system_instruction=SYSTEM_INSTRUCTION
                )
                response = model.generate_content(user_message)
                logger.info("✅ [ROUTER] Gemini successfully fulfilled the request.")
                return response.text
            except Exception as e:
                logger.warning(f"⚠️ [ROUTER] Gemini failed (Quota or Network): {str(e)[:60]}")
                # Eğer kota hatasıysa bir sonraki aşamaya geç

        # 2. STRATEJİ: GEMINI PATLARSA DOĞRUDAN GROQ (LLAMA 3) DENE (Çok hızlı ve kotası geniştir)
        if self.groq_key:
            try:
                logger.info("[ROUTER] Gemini failed. Switching to Groq Cloud (Llama-3)...")
                import requests
                headers = {
                    "Authorization": f"Bearer {self.groq_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": "llama3-8b-8192",
                    "messages": [
                        {"role": "system", "content": SYSTEM_INSTRUCTION},
                        {"role": "user", "content": user_message}
                    ]
                }
                response = requests.post("https://api.groq.com/openai/v1/chat/completions", json=payload, timeout=15)
                if response.status_code == 200:
                    logger.info("✅ [ROUTER] Groq successfully fulfilled the request.")
                    return response.json()["choices"][0]["message"]["content"]
                else:
                    logger.warning(f"⚠️ [ROUTER] Groq API returned status code: {response.status_code}")
            except Exception as e:
                logger.warning(f"⚠️ [ROUTER] Groq fallback failed: {e}")

        # 3. STRATEJİ: YEDEK OLARAK OPENAI (GPT-4o-mini) DENE
        if self.openai_key and OpenAI:
            try:
                logger.info("[ROUTER] Switching to OpenAI (GPT-4o-mini)...")
                client = OpenAI(api_key=self.openai_key)
                completion = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": SYSTEM_INSTRUCTION},
                        {"role": "user", "content": user_message}
                    ],
                    timeout=15
                )
                logger.info("✅ [ROUTER] OpenAI successfully fulfilled the request.")
                return completion.choices[0].message.content
            except Exception as e:
                logger.warning(f"⚠️ [ROUTER] OpenAI fallback failed: {e}")

        # 4. STRATEJİ: TÜM APILAR ÇÖKERSE LOCAL SOAR FORENSIC ENGINE ÇALIŞSIN
        logger.error("🚨 [ROUTER CRITICAL] All LLM provider quotas are exhausted! Routing to local fallback.")
        return self._execute_local_fallback_soar(user_message)

    def _execute_local_fallback_soar(self, raw_message: str) -> str:
        clean_target = raw_message.replace("Investigate this target:", "").strip()
        return f"""
⚠️ **[SYSTEM ALERT] ChatSecOps AI Agent Orchestration Pool is Fully Exhausted.**
*Status:* All AI Provider Gateways (Gemini, Groq, OpenAI) returned Quota (429) limits.

*Target Dispatched:* `{clean_target}`
*SOC Action Required:* AI summary is currently offline. Please access your local Uvicorn API docs (`http://127.0.0.1:8000/docs`) to review the automated LightGBM model outputs, SQLite threat memories, and MITRE mapping matrices manually.
"""

# Slack bota export edilen güvenli singleton nesne
secops_agent = MultiLLMRouterAgent()