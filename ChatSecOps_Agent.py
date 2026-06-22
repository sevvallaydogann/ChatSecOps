import os
import json
import logging
from typing import Dict, Any
import google.generativeai as genai

logger = logging.getLogger(__name__)

class ChatSecOpsAgent:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        if self.api_key:
            genai.configure(api_key=self.api_key)
        
        # main.py'daki gibi en kararlı ve güncel modelleri sırayla deniyoruz
        self.model_priority = [
            'models/gemini-1.5-flash-latest',
            'models/gemini-1.5-flash',
            'models/gemini-1.5-flash-8b', # Çok daha hafif ve kotası rahattır
            'models/gemini-2.5-flash'
        ]
        
        self.system_instruction = """
        You are the ChatSecOps Autonomous Cyber Security Threat Intelligence Agent.
        Your goal is to investigate indicator of compromises (IOCs), domains, and URLs sent by users via Slack.
        Synthesize everything into a final English response with clear sections: Verdict, Risk Score, Evidence, and Actions.
        """
        
        self.gemini_model = self._load_best_model()

    def _load_best_model(self):
        """API v1/v1beta uyumluluğu için en kararlı modeli dinamik olarak seçer."""
        # Eğer sistemde listeleme yapılabiliyorsa mevcut modelleri kontrol et
        try:
            available_models = [m.name for m in genai.list_models() if 'generateContent' in m.supported_generation_methods]
        except Exception:
            available_models = []

        # Öncelikli listemizden çevrimiçi/desteklenen ilk modeli seçmeye çalış
        for model_name in self.model_priority:
            if not available_models or model_name in available_models:
                try:
                    logger.info(f"[AGENT] Trying model initialization: {model_name}")
                    test_model = genai.GenerativeModel(
                        model_name=model_name,
                        system_instruction=self.system_instruction
                    )
                    # Ufak bir ping/test isteği göndererek modelin çalışıp çalışmadığını doğrula
                    test_model.generate_content("ping")
                    logger.info(f"✅ [AGENT] Successfully loaded model: {model_name}")
                    return test_model
                except Exception as e:
                    logger.warning(f"⚠️ [AGENT] Model {model_name} failed: {str(e)[:100]}")
                    continue
        
        # Hiçbiri olmazsa fallback olarak doğrudan genel bir model ismi ata
        logger.error("[AGENT] None of the preferred models initialized. Using fallback gemini-pro.")
        return genai.GenerativeModel(model_name='models/gemini-pro', system_instruction=self.system_instruction)

    def handle_message(self, user_message: str) -> str:
        """ Gelen mesajı güvenli şekilde seçilen modele gönderir. """
        logger.info(f"AI Agent task started: {user_message}")
        if not self.gemini_model:
            return "❌ Agent error: No compliant Gemini model could be initialized."
            
        try:
            response = self.gemini_model.generate_content(user_message)
            return response.text
        except Exception as e:
            logger.error(f"Agent workflow failed: {e}")
            return f"❌ Agent error: {str(e)}"

# Slack bota export edilen singleton nesne
secops_agent = ChatSecOpsAgent()