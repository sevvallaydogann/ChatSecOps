"""
ChatSecOps_Pivot.py - IOC Chain Tracking (Feature 2)
=====================================================
When a domain is analyzed, it detects other domains sharing
the same IP and automatically queues them for analysis.

Flow:
  1. Domain is analyzed → IP is detected
  2. PivotEngine steps in:
     a. Are there other domains on this IP in our DB?
     b. Does Shodan have a hostname list for this IP?
  3. If a new domain is found → automatic analysis queue
  4. Results are sent to Slack + saved to DB

Infinite loop protection:
  - Each domain runs in the pivot chain at most PIVOT_MAX_DEPTH times
  - Those already analyzed in the same session are skipped
"""

import sqlite3
import requests
import logging
import os
import time
from datetime import datetime
from typing import List, Dict, Optional, Set

logger = logging.getLogger(__name__)

# Maximum number of new domains to be analyzed in a pivot session
PIVOT_MAX_DEPTH = 5

# Wait time between pivot analyses (seconds)
# To prevent the main analysis from slowing down
PIVOT_DELAY = 2


class PivotEngine:
    """
    IOC Chain Tracking Engine.
    
    Centering around an IP address:
    - Finds all connected domains in our database
    - Fetches the hostname list of the same IP from Shodan
    - Puts new domains in the analysis queue
    - Generates the chain report
    """

    def __init__(self, db_path: str = "chatsecops_memory.db"):
        self.db_path = db_path
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.backend_api = os.getenv("BACKEND_API_URL", "http://localhost:8000")

    # =========================================================================
    # SOURCE 1: OUR OWN DATABASE
    # =========================================================================

    def get_cohosted_from_db(self, ip_address: str, exclude_domain: str) -> List[Dict]:
        """
        Fetches domains on the same IP from ip_clusters + domain_analysis tables.
        exclude_domain: the domain that started the chain, so we don't add it again.
        """
        if not ip_address or ip_address == "N/A":
            return []

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                SELECT 
                    domain,
                    risk_score,
                    prediction,
                    MAX(timestamp) as last_seen
                FROM domain_analysis
                WHERE ip_address = ?
                  AND domain != ?
                GROUP BY domain
                ORDER BY risk_score DESC
            """, (ip_address, exclude_domain))

            rows = cursor.fetchall()
            conn.close()

            results = []
            for domain, risk_score, prediction, last_seen in rows:
                results.append({
                    "domain": domain,
                    "risk_score": round(risk_score, 1) if risk_score else 0.0,
                    "prediction": prediction,
                    "source": "our_db",
                    "last_seen": datetime.fromtimestamp(last_seen).strftime("%Y-%m-%d") if last_seen else "N/A"
                })

            logger.info(f"[PIVOT] {len(results)} co-hosted domains found in DB (IP: {ip_address})")
            return results

        except Exception as e:
            logger.error(f"[PIVOT] DB query error: {e}")
            return []

    # =========================================================================
    # SOURCE 2: SHODAN - FETCH HOSTNAMES ON THE SAME IP
    # =========================================================================

    def get_cohosted_from_shodan(self, ip_address: str, exclude_domain: str) -> List[Dict]:
        """
        Fetches the hostname list of the IP from Shodan.
        This list may contain domains we haven't analyzed before.
        """
        if not self.shodan_key:
            logger.warning("[PIVOT] No Shodan API key, skipping this source")
            return []

        if not ip_address or ip_address == "N/A":
            return []

        try:
            # Shodan REST API - requires no library
            url = f"https://api.shodan.io/shodan/host/{ip_address}"
            params = {"key": self.shodan_key}
            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 404:
                logger.info(f"[PIVOT] {ip_address} not found on Shodan")
                return []

            if response.status_code != 200:
                logger.warning(f"[PIVOT] Shodan HTTP {response.status_code}")
                return []

            data = response.json()
            hostnames = data.get("hostnames", [])

            results = []
            for hostname in hostnames:
                # Skip itself, empty ones, and wildcards
                if not hostname or hostname == exclude_domain or hostname.startswith("*"):
                    continue

                results.append({
                    "domain": hostname,
                    "risk_score": None,       # not yet analyzed
                    "prediction": None,
                    "source": "shodan",
                    "last_seen": "New"        # seeing for the first time
                })

            logger.info(f"[PIVOT] {len(results)} hostnames retrieved from Shodan (IP: {ip_address})")
            return results

        except requests.exceptions.Timeout:
            logger.warning("[PIVOT] Shodan timeout")
            return []
        except Exception as e:
            logger.error(f"[PIVOT] Shodan error: {e}")
            return []

    # =========================================================================
    # MAIN FUNCTION: RUN PIVOT ANALYSIS
    # =========================================================================

    def run_pivot(
        self,
        trigger_domain: str,
        ip_address: str,
        trigger_risk_score: float,
        already_analyzed: Optional[Set[str]] = None
    ) -> Dict:
        """
        Starts the pivot chain.

        Parameters:
            trigger_domain:     The domain that initiated the chain
            ip_address:         The detected IP
            trigger_risk_score: Risk score of the initiating domain
            already_analyzed:   Set of domains already analyzed in this session (loop protection)

        Returns:
            {
                "pivot_triggered": bool,
                "ip_address": str,
                "total_related": int,
                "db_domains": [...],
                "shodan_domains": [...],
                "auto_analyzed": [...],
                "slack_message": str
            }
        """

        if already_analyzed is None:
            already_analyzed = {trigger_domain}

        logger.info(f"[PIVOT] Chain started: {trigger_domain} → IP: {ip_address}")

        # 1. Collect domains from both sources
        db_domains = self.get_cohosted_from_db(ip_address, trigger_domain)
        shodan_domains = self.get_cohosted_from_shodan(ip_address, trigger_domain)

        # 2. Merge, remove duplicates
        all_related = {}
        for d in db_domains:
            all_related[d["domain"]] = d
        for d in shodan_domains:
            # Add if not in DB, if present set source to "both"
            if d["domain"] in all_related:
                all_related[d["domain"]]["source"] = "both"
            else:
                all_related[d["domain"]] = d

        related_list = list(all_related.values())
        total_related = len(related_list)

        if total_related == 0:
            logger.info(f"[PIVOT] No pivot found for {trigger_domain}")
            return {
                "pivot_triggered": False,
                "ip_address": ip_address,
                "total_related": 0,
                "db_domains": [],
                "shodan_domains": [],
                "auto_analyzed": [],
                "slack_message": None
            }

        # 3. Automatically analyze NEW domains (not in DB) from Shodan
        new_domains = [
            d for d in related_list
            if d["source"] in ("shodan", "both")
            and d["domain"] not in already_analyzed
            and d["risk_score"] is None  # not yet analyzed
        ]

        auto_analyzed = []

        # Analyze a maximum of PIVOT_MAX_DEPTH new domains
        domains_to_analyze = new_domains[:PIVOT_MAX_DEPTH]

        for domain_info in domains_to_analyze:
            domain = domain_info["domain"]
            already_analyzed.add(domain)

            logger.info(f"[PIVOT] Starting automatic analysis: {domain}")
            time.sleep(PIVOT_DELAY)  # API rate limit protection

            try:
                response = requests.get(
                    f"{self.backend_api}/enrich-and-summarize/domain/{domain}",
                    timeout=90
                )

                if response.status_code == 200:
                    result = response.json()
                    # Keeping original JSON keys from backend response
                    model_data = result.get("ham_veriler", {}).get("kendi_modelimiz", {})
                    risk = float(model_data.get("risk_skoru_yuzde", "0").replace("%", ""))
                    pred = model_data.get("tahmin_sinifi", 0)

                    auto_analyzed.append({
                        "domain": domain,
                        "risk_score": risk,
                        "prediction": pred,
                        "verdict": "MALICIOUS" if pred == 1 else "SAFE"
                    })

                    # Update all_related
                    if domain in all_related:
                        all_related[domain]["risk_score"] = risk
                        all_related[domain]["prediction"] = pred

                    logger.info(f"[PIVOT] ✅ {domain} analysis completed (Risk: {risk}%)")

                else:
                    logger.warning(f"[PIVOT] {domain} analysis failed: HTTP {response.status_code}")

            except requests.exceptions.Timeout:
                logger.warning(f"[PIVOT] {domain} analysis timeout")
            except Exception as e:
                logger.error(f"[PIVOT] {domain} analysis error: {e}")

        # 4. Build the Slack message
        slack_message = self._build_slack_message(
            trigger_domain=trigger_domain,
            ip_address=ip_address,
            trigger_risk_score=trigger_risk_score,
            related_domains=list(all_related.values()),
            auto_analyzed=auto_analyzed
        )

        return {
            "pivot_triggered": True,
            "ip_address": ip_address,
            "total_related": total_related,
            "db_domains": db_domains,
            "shodan_domains": [d for d in related_list if d["source"] in ("shodan", "both")],
            "auto_analyzed": auto_analyzed,
            "slack_message": slack_message
        }

    # =========================================================================
    # BUILD SLACK MESSAGE
    # =========================================================================

    def _build_slack_message(
        self,
        trigger_domain: str,
        ip_address: str,
        trigger_risk_score: float,
        related_domains: List[Dict],
        auto_analyzed: List[Dict]
    ) -> str:
        """
        Formats the pivot chain findings for Slack.
        """
        malicious_count = sum(
            1 for d in related_domains
            if d.get("prediction") == 1 or (d.get("risk_score") and d["risk_score"] >= 70)
        )

        # Header section
        lines = [
            f"🕸️ *IOC Pivot Chain Detected*",
            f"",
            f"*Trigger Domain:* `{trigger_domain}` (Risk: {trigger_risk_score:.0f}%)",
            f"*Shared IP:* `{ip_address}`",
            f"*Total Related Domains:* {len(related_domains)}",
        ]

        if malicious_count > 0:
            lines.append(f"*⚠️ Malicious Detection:* {malicious_count} domains on this IP are marked as malicious!")
        
        lines.append("")

        # Found in DB
        db_found = [d for d in related_domains if d["source"] in ("our_db", "both")]
        if db_found:
            lines.append("*📁 Domains Seen on This IP in Our Database:*")
            for d in db_found[:5]:  # Show max 5
                risk = d.get("risk_score", 0) or 0
                icon = "🔴" if risk >= 70 else "🟡" if risk >= 30 else "🟢"
                lines.append(f"  {icon} `{d['domain']}` — Risk: {risk:.0f}% | Last seen: {d.get('last_seen', 'N/A')}")
            if len(db_found) > 5:
                lines.append(f"  _...and {len(db_found) - 5} more domains_")
            lines.append("")

        # Automatically analyzed
        if auto_analyzed:
            lines.append("*🤖 Automatically Analyzed (New from Shodan):*")
            for d in auto_analyzed:
                icon = "🔴" if d["prediction"] == 1 else "🟢"
                lines.append(f"  {icon} `{d['domain']}` — {d['verdict']} ({d['risk_score']:.0f}%)")
            lines.append("")

        # Campaign warning
        if malicious_count >= 3:
            lines.append("🚨 *CAMPAIGN WARNING:* Multiple malicious domains detected on this IP.")
            lines.append("Shared infrastructure usage — possible coordinated attack campaign.")

        return "\n".join(lines)


# =============================================================================
# SINGLETON
# =============================================================================
pivot_engine = PivotEngine()