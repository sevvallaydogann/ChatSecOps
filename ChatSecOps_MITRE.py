"""
ChatSecOps_MITRE.py — MITRE ATT&CK Taxonomic Mapping Engine (Feature 5)
=========================================================================

Girdi sinyalleri:
  - SHAP feature attributions (Entropy, TLD, HasSPFInfo, CreationDate...)
  - URL parser findings (brand impersonation, /login path, open redirect)
  - Shodan data (open ports, CVEs, HTTP transport)
  - ML risk score
  - VirusTotal results
  - Pivot chain results

Çıktı:
  - Tetiklenen ATT&CK technique'lerin listesi (ID, isim, gerekçe, güven)
  - Slack için formatlanmış metin
  - PDF'e eklenecek tactic summary

Makalede belirtilen 3 ana teknik + ek 3 teknik:
  T1566.002 — Spearphishing Link
  T1568.002 — Domain Generation Algorithms
  T1071.001 — Web Protocols C2
  T1583.001 — Acquire Infrastructure: Domains
  T1598.003 — Phishing for Information: Spearphishing Link
  T1190    — Exploit Public-Facing Application
"""

import logging
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# =============================================================================
# ATT&CK TEKNİK KATALOĞU
# =============================================================================

TECHNIQUE_CATALOG = {
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversary sends spearphishing messages containing malicious links.",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "T1568.002": {
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries use DGA to procedurally generate domain names for C2.",
        "url": "https://attack.mitre.org/techniques/T1568/002/"
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries communicate using HTTP/HTTPS to blend with normal traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/001/"
    },
    "T1583.001": {
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "tactic_id": "TA0042",
        "description": "Adversaries register domains to use during operations.",
        "url": "https://attack.mitre.org/techniques/T1583/001/"
    },
    "T1598.003": {
        "name": "Phishing for Information: Spearphishing Link",
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "description": "Adversaries send phishing messages with links to harvest credentials.",
        "url": "https://attack.mitre.org/techniques/T1598/003/"
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries exploit weakness in internet-facing system.",
        "url": "https://attack.mitre.org/techniques/T1190/"
    },
}

# Bilinen C2 portları (Shodan ile karşılaştırılır)
KNOWN_C2_PORTS = {
    4444, 8080, 8443, 8888, 9999, 1337, 31337,
    6666, 6667, 6668, 6669,  # IRC
    8000, 9090, 3333, 5555,
    2222, 4545, 7777
}


# =============================================================================
# MAPPING ENGINE
# =============================================================================

class MITREMapper:
    """
    Deterministik MITRE ATT&CK eşleştirme motoru.

    Makale Section 3.7'de tanımlandığı üzere:
    "The module implements a deterministic ingestion mapper linked straight
    to the open-source MITRE ATT&CK matrix registry dataset."
    """

    def map(self, analysis_result: dict) -> dict:
        """
        Ana eşleştirme fonksiyonu. Analiz sonucunu alır, ATT&CK tekniklerini döner.

        Parametreler:
            analysis_result: enrich_and_summarize_domain'in döndürdüğü tam response dict

        Döndürür:
            {
                "techniques": [...],       # Tetiklenen teknikler listesi
                "tactic_summary": str,     # Slack/PDF için özet
                "total_triggered": int,    # Toplam tetiklenen teknik sayısı
                "highest_tactic": str      # En kritik tactic
            }
        """
        triggered = []

        # Sinyalleri çıkar — None değerlere karşı güvenli erişim
        ham_veriler  = analysis_result.get("ham_veriler") or {}
        model_data   = ham_veriler.get("kendi_modelimiz") or {}
        vt_data      = ham_veriler.get("virustotal") or {}
        osint_data   = ham_veriler.get("osint") or {}
        url_analysis = analysis_result.get("url_analysis") or {}
        pivot_chain  = analysis_result.get("pivot_chain") or {}

        risk_score   = self._parse_risk(model_data.get("risk_skoru_yuzde", "0%"))
        xai_summary  = model_data.get("xai_ozeti") or ""
        top_features = model_data.get("ust_ozellikler") or []
        domain       = analysis_result.get("domain") or ""

        shodan_data  = osint_data.get("shodan") or {}
        open_ports   = set(shodan_data.get("ports") or [])
        vulns        = shodan_data.get("vulns") or []

        vt_malicious = vt_data.get("malicious", 0) if isinstance(vt_data, dict) else 0

        # ------------------------------------------------------------------
        # T1566.002 — Spearphishing Link
        # Tetikleyici: URL engine brand impersonation, /login path, open redirect
        # ------------------------------------------------------------------
        url_findings = url_analysis.get("findings", [])
        url_risk_level = url_analysis.get("url_risk_level", "LOW")

        spear_reasons = []
        if any("marka taklidi" in f.lower() or "brand impersonation" in f.lower()
               for f in url_findings):
            spear_reasons.append("brand impersonation detected in subdomain")
        if any("login" in f.lower() or "signin" in f.lower() or "verify" in f.lower()
               for f in url_findings):
            spear_reasons.append("high-risk login/verify path in URL")
        if any("open redirect" in f.lower() or "açık yönlendirme" in f.lower()
               for f in url_findings):
            spear_reasons.append("open redirect query chain detected")
        if url_risk_level in ("HIGH", "CRITICAL"):
            spear_reasons.append(f"URL structural risk level: {url_risk_level}")

        if spear_reasons:
            confidence = "HIGH" if len(spear_reasons) >= 2 else "MEDIUM"
            triggered.append(self._build(
                tech_id="T1566.002",
                confidence=confidence,
                reasons=spear_reasons
            ))

        # ------------------------------------------------------------------
        # T1568.002 — Domain Generation Algorithms (DGA)
        # Tetikleyici: SHAP'ta yüksek Entropy + karakter dağılımı anomalisi
        # ------------------------------------------------------------------
        dga_reasons = []

        # SHAP feature listesinde Entropy yüksek sırada mı?
        entropy_triggered = self._feature_in_top(top_features, "entropy", xai_summary)
        if entropy_triggered:
            dga_reasons.append("Entropy ranked as top SHAP feature (mean |SHAP|=3.20) — indicates algorithmically generated string")

        # NumericRatio, VowelRatio, ConsonantRatio anomalisi
        char_dist_triggered = (
            self._feature_in_top(top_features, "numericratio", xai_summary) or
            self._feature_in_top(top_features, "vowelratio", xai_summary) or
            self._feature_in_top(top_features, "consonantratio", xai_summary)
        )
        if char_dist_triggered:
            dga_reasons.append("Anomalous character distribution (numeric/vowel/consonant ratio) in top SHAP features")

        # Çok yüksek risk + kısa domain → DGA pattern
        if risk_score >= 80 and len(domain.replace(".","")) >= 12:
            dga_reasons.append(f"High ML risk ({risk_score:.0f}%) with long domain name — DGA behavioral pattern")

        if dga_reasons:
            confidence = "HIGH" if entropy_triggered else "MEDIUM"
            triggered.append(self._build(
                tech_id="T1568.002",
                confidence=confidence,
                reasons=dga_reasons
            ))

        # ------------------------------------------------------------------
        # T1071.001 — Web Protocols C2
        # Tetikleyici: Shodan'da HTTP/C2 portları veya Pivot'ta paylaşılan altyapı
        # ------------------------------------------------------------------
        c2_reasons = []

        # HTTP (şifresiz) transport
        if url_analysis and url_analysis.get("components", {}).get("scheme") == "http":
            c2_reasons.append("Unencrypted HTTP transport detected — C2 blending with web traffic")

        # Shodan'da bilinen C2 portları
        c2_ports_found = open_ports & KNOWN_C2_PORTS
        if c2_ports_found:
            c2_reasons.append(f"Known C2 ports open via Shodan: {sorted(c2_ports_found)}")

        # CVE güvenlik açıkları
        if vulns:
            c2_reasons.append(f"CVE vulnerabilities found via Shodan: {vulns[:3]}")

        # Pivot ile paylaşılan zararlı altyapı
        if pivot_chain.get("triggered") and pivot_chain.get("total_related", 0) >= 2:
            c2_reasons.append(
                f"Pivot Engine found {pivot_chain['total_related']} co-hosted domains "
                f"on shared IP — coordinated C2 infrastructure likely"
            )

        if c2_reasons:
            confidence = "HIGH" if (c2_ports_found or vulns) else "MEDIUM"
            triggered.append(self._build(
                tech_id="T1071.001",
                confidence=confidence,
                reasons=c2_reasons
            ))

        # ------------------------------------------------------------------
        # T1583.001 — Acquire Infrastructure: Domains
        # Tetikleyici: CreationDate SHAP'ta üst sıralarda + yeni kayıt
        # ------------------------------------------------------------------
        infra_reasons = []

        if self._feature_in_top(top_features, "creationdate", xai_summary):
            infra_reasons.append("CreationDate ranked as top SHAP feature — freshly registered domain pattern")

        # Üst TLD'ler (ücretsiz, kötüye kullanılan)
        abused_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".ru", ".xyz", ".top", ".click"}
        domain_lower = domain.lower()
        for tld in abused_tlds:
            if domain_lower.endswith(tld):
                infra_reasons.append(f"Free/abused TLD '{tld}' — documented high abuse rate (>40%)")
                break

        if self._feature_in_top(top_features, "tld_grouped_tk", xai_summary) or \
           self._feature_in_top(top_features, "tld_grouped_ml", xai_summary):
            infra_reasons.append("Free TLD (.tk/.ml) ranked as top SHAP feature (mean |SHAP|=2.80/2.40)")

        if infra_reasons:
            triggered.append(self._build(
                tech_id="T1583.001",
                confidence="MEDIUM",
                reasons=infra_reasons
            ))

        # ------------------------------------------------------------------
        # T1598.003 — Phishing for Information: Spearphishing Link
        # Tetikleyici: Credential harvesting pattern (login + redirect + brand)
        # Devreye girme koşulu: T1566.002 zaten tetiklendiyse VE redirect var
        # ------------------------------------------------------------------
        already_spear = any(t["technique_id"] == "T1566.002" for t in triggered)
        has_redirect = any("redirect" in f.lower() for f in url_findings)
        missing_spf = self._feature_in_top(top_features, "hasspfinfo", xai_summary)

        if already_spear and (has_redirect or missing_spf):
            reasons = []
            if has_redirect:
                reasons.append("Open redirect to harvest credentials from spoofed landing page")
            if missing_spf:
                reasons.append("HasSPFInfo in top SHAP features — missing email authentication indicates spoofed sender infrastructure")
            triggered.append(self._build(
                tech_id="T1598.003",
                confidence="MEDIUM",
                reasons=reasons
            ))

        # ------------------------------------------------------------------
        # T1190 — Exploit Public-Facing Application
        # Tetikleyici: Shodan'da CVE + yüksek risk
        # ------------------------------------------------------------------
        if vulns and risk_score >= 60:
            triggered.append(self._build(
                tech_id="T1190",
                confidence="HIGH" if len(vulns) >= 2 else "MEDIUM",
                reasons=[
                    f"{len(vulns)} CVE vulnerability/ies identified via Shodan: {vulns[:3]}",
                    f"High ML risk score ({risk_score:.0f}%) corroborates active exploitation likelihood"
                ]
            ))

        # ------------------------------------------------------------------
        # Sonuç
        # ------------------------------------------------------------------
        tactic_summary = self._build_summary(triggered, domain)

        highest_tactic = self._get_highest_tactic(triggered)

        logger.info(f"[MITRE] {domain}: {len(triggered)} teknik eşleşti — {[t['technique_id'] for t in triggered]}")

        return {
            "techniques": triggered,
            "tactic_summary": tactic_summary,
            "total_triggered": len(triggered),
            "highest_tactic": highest_tactic
        }

    # =========================================================================
    # YARDIMCI FONKSİYONLAR
    # =========================================================================

    def _parse_risk(self, risk_str: str) -> float:
        try:
            return float(str(risk_str).replace("%", "").strip())
        except:
            return 0.0

    def _feature_in_top(self, top_features: list, feature_name: str, xai_text: str) -> bool:
        """
        Belirtilen feature'ın SHAP top listesinde veya XAI özetinde olup olmadığını kontrol eder.
        """
        feature_lower = feature_name.lower()

        # top_features listesi varsa (JSON array veya string list)
        if top_features:
            for f in top_features:
                f_str = str(f).lower()
                if feature_lower in f_str:
                    return True

        # xai_ozeti string'inde ara (fallback)
        if xai_text and feature_lower in xai_text.lower():
            return True

        return False

    def _build(self, tech_id: str, confidence: str, reasons: list) -> dict:
        """Bir teknik dict'i oluşturur."""
        catalog = TECHNIQUE_CATALOG.get(tech_id, {})
        return {
            "technique_id": tech_id,
            "technique_name": catalog.get("name", "Unknown"),
            "tactic": catalog.get("tactic", "Unknown"),
            "tactic_id": catalog.get("tactic_id", ""),
            "confidence": confidence,  # HIGH / MEDIUM / LOW
            "reasons": reasons,
            "mitre_url": catalog.get("url", f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/")
        }

    def _get_highest_tactic(self, triggered: list) -> str:
        """En kritik tactic'i döner (Initial Access > C2 > Resource Dev)."""
        priority = ["Initial Access", "Command and Control", "Reconnaissance", "Resource Development"]
        tactics_found = {t["tactic"] for t in triggered}
        for tactic in priority:
            if tactic in tactics_found:
                return tactic
        return tactics_found.pop() if tactics_found else "N/A"

    def _build_summary(self, triggered: list, domain: str) -> str:
        """Slack ve PDF için özet metin üretir."""
        if not triggered:
            return f"✅ No MITRE ATT&CK techniques triggered for `{domain}`."

        confidence_icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

        lines = [f"🛡️ *MITRE ATT&CK Mapping — {domain}*", ""]

        for t in triggered:
            icon = confidence_icon.get(t["confidence"], "⚪")
            lines.append(
                f"{icon} `{t['technique_id']}` — *{t['technique_name']}*  "
                f"[{t['tactic']}] | Confidence: {t['confidence']}"
            )
            for r in t["reasons"][:2]:  # Max 2 gerekçe
                lines.append(f"    › {r}")
            lines.append("")

        # Tactic özeti
        tactics = list({t["tactic"] for t in triggered})
        lines.append(f"📌 *Tactics covered:* {' · '.join(tactics)}")

        return "\n".join(lines)

    def format_for_slack_block(self, mitre_result: dict) -> list:
        """
        Slack block kit formatında döner — her teknik için gerekçeleriyle birlikte.
        """
        if not mitre_result or mitre_result.get("total_triggered", 0) == 0:
            return []

        confidence_icon  = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}
        confidence_label = {"HIGH": "High Confidence", "MEDIUM": "Medium Confidence", "LOW": "Low Confidence"}
        tactic_icon      = {
            "Initial Access":        "🚪",
            "Command and Control":   "📡",
            "Reconnaissance":        "🔭",
            "Resource Development":  "🏗️",
            "Execution":             "⚙️",
            "Persistence":           "🔒",
        }

        techniques = mitre_result.get("techniques", [])
        total      = mitre_result.get("total_triggered", 0)
        highest    = mitre_result.get("highest_tactic", "")

        # Taktikler özeti
        tactics_covered = list({t["tactic"] for t in techniques})
        tactics_str = " · ".join(
            f"{tactic_icon.get(tac, '🎯')} {tac}" for tac in tactics_covered
        )

        blocks = [
            {"type": "divider"},
            # Başlık
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*🛡️ MITRE ATT&CK Taxonomic Mapping*\n"
                        f"*{total} Technique{'s' if total > 1 else ''} Identified* "
                        f"| Primary Tactic: *{highest}*"
                    )
                }
            },
            {"type": "divider"},
        ]

        # Her teknik için ayrı blok
        for t in techniques:
            icon      = confidence_icon.get(t["confidence"], "⚪")
            conf_lbl  = confidence_label.get(t["confidence"], t["confidence"])
            tac_icon  = tactic_icon.get(t["tactic"], "🎯")
            reasons   = t.get("reasons", [])

            # Gerekçeleri formatla
            evidence_lines = "\n".join(f"› _{r}_" for r in reasons[:3])

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{icon} *<{t['mitre_url']}|{t['technique_id']}> — {t['technique_name']}*\n"
                        f"{tac_icon} *Tactic:* {t['tactic']}   |   *Confidence:* {conf_lbl}\n"
                        f"{evidence_lines}"
                    )
                }
            })

        # Taktikler özet footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"📌 *Tactics Covered:* {tactics_str}"
                }
            ]
        })

        return blocks


# =============================================================================
# SİNGLETON
# =============================================================================
mitre_mapper = MITREMapper()
