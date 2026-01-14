import os

class ThreatIntelligence:
    def __init__(self):
        # Görsel kanıt için ücretsiz ekran görüntüsü servisi (thum.io)
        self.screenshot_service = "https://image.thum.io/get/width/600/crop/800/"

    def get_visual_evidence(self, domain: str):
        """Sitenin canlı ekran görüntüsü linkini oluşturur."""
        return f"{self.screenshot_service}http://{domain}"

    def get_hunting_logic(self):
        """Gemini için gelişmiş Tehdit Avcılığı talimatı."""
        return """
        --- STRATEJİK TEHDİT AVCILIĞI (THREAT HUNTING) ---
        Analizini bitirirken, SOC ekibi için şu teknik sorguları da ekle:
        1. **Splunk (SPL):** Bu domain veya IP ile ilgili logları bulacak sorgu.
        2. **Elasticsearch (KQL):** Anomali tespiti için gerekli sorgu.
        Bu sorgular, modelin bulduğu riskli öznitelikleri (IP, ASN, TLD) baz almalıdır.
        """

# Motoru dışarıya aç
intel_engine = ThreatIntelligence()