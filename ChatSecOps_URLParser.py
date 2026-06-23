"""
ChatSecOps_URLParser.py - Automated Phishing URL Parsing (Feature 1)
======================================================================
The current ML model only works on the domain.
This module analyzes the rest of the URL (path, query, subdomain structure)
to produce a "URL Risk Boost" score.

Final score = min(100, ML_score + URL_boost)

Flow:
  1. Normalize URL (hxxps, defanged, [.] notation)
  2. Parse into components using urllib.parse
  3. Calculate rule-based risk score for each component
  4. Generate a reasoned report
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Tuple


# =============================================================================
# RULE-BASED RISK RULES
# Each rule: (points, description)
# =============================================================================

# High-risk keywords found in the Path
PATH_HIGH_RISK_KEYWORDS = {
    "login":        (15, "Login page impersonation"),
    "signin":       (15, "Sign-in page impersonation"),
    "sign-in":      (15, "Sign-in page impersonation"),
    "verify":       (15, "Verification page impersonation"),
    "verification": (15, "Verification page impersonation"),
    "secure":       (12, "Security page impersonation"),
    "security":     (12, "Security page impersonation"),
    "update":       (12, "Update page impersonation"),
    "account":      (10, "Account page impersonation"),
    "banking":      (18, "Banking page impersonation"),
    "bank":         (15, "Banking page impersonation"),
    "password":     (15, "Password page impersonation"),
    "wallet":       (12, "Wallet page impersonation"),
    "confirm":      (10, "Confirmation page impersonation"),
    "recover":      (10, "Recovery page impersonation"),
    "reset":        (10, "Reset page impersonation"),
    "support":      (5,  "Support page impersonation"),
    "invoice":      (8,  "Invoice page impersonation"),
    "payment":      (12, "Payment page impersonation"),
    "checkout":     (8,  "Checkout page impersonation"),
}

# Low-to-medium risk keywords found in the Path
PATH_MEDIUM_RISK_KEYWORDS = {
    "admin":        (8, "Admin panel targeted"),
    "wp-admin":     (8, "WordPress admin targeted"),
    "webmail":      (6, "Webmail targeted"),
    "cpanel":       (6, "cPanel targeted"),
}

# Query parameters used for redirection — open redirect indicator
REDIRECT_PARAMS = {
    "redirect", "redirect_to", "redirect_url",
    "url", "goto", "next", "return",
    "returnurl", "return_url", "target",
    "destination", "dest", "forward", "redir",
    "link", "continue", "ref", "referer",
    "callback", "to", "from"
}

# Domains of major brands — for subdomain impersonation detection
BRAND_DOMAINS = {
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "instagram", "twitter", "linkedin", "netflix", "spotify",
    "dropbox", "github", "yahoo", "outlook", "hotmail", "gmail",
    "bankofamerica", "chase", "wells", "citibank", "hsbc",
    "garanti", "akbank", "isbank", "yapikredi", "ziraat",
    "steam", "valve", "blizzard", "epicgames",
    "dhl", "fedex", "ups", "tnt", "ptt"
}


class URLParser:
    """
    Phishing URL Analysis Engine.
    
    Usage:
        parser = URLParser()
        result = parser.analyze("hxxps://paypal-security.tk/login?redirect=paypal.com")
        print(result["url_risk_boost"])   # 47
        print(result["findings"])         # List of findings
    """

    def normalize_url(self, raw_url: str) -> str:
        """
        Normalizes common defanged URL formats found in security reports.
        
        Examples:
          hxxps://example.com  → https://example.com
          hxxp://example[.]com → http://example.com
          example[.]com/path   → http://example.com/path
        """
        url = raw_url.strip()

        # hxxp / hxxps → http / https
        url = re.sub(r'^hxxps?://', lambda m: m.group(0).replace('hxxp', 'http'), url, flags=re.IGNORECASE)

        # [.] → .  (defanged dot)
        url = url.replace("[.]", ".").replace("(.", ".").replace(".)", ".")

        # [:] → : (defanged colon)
        url = url.replace("[:]", ":")

        # Add scheme if missing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        return url

    def extract_domain_from_url(self, url: str) -> str:
        """
        Extracts only the domain part from the URL.
        This domain will be fed into the existing ML model.
        
        https://paypal-security.tk/login → paypal-security.tk
        """
        try:
            parsed = urlparse(self.normalize_url(url))
            # Remove www. prefix
            netloc = parsed.netloc.lower()
            if netloc.startswith("www."):
                netloc = netloc[4:]
            return netloc
        except:
            return url

    def _analyze_path(self, path: str) -> Tuple[int, List[str]]:
        """
        Analyzes the URL path.
        Returns: (total score, list of findings)
        """
        score = 0
        findings = []
        path_lower = path.lower()

        # Split path tokens (by /)
        tokens = set(re.split(r'[/\-_.]', path_lower))
        tokens = {t for t in tokens if t}  # remove empty tokens

        # High-risk keywords
        for keyword, (points, description) in PATH_HIGH_RISK_KEYWORDS.items():
            if keyword in tokens or keyword in path_lower:
                score += points
                findings.append(f"⚠️ '{keyword}' detected in Path — {description} (+{points} points)")
                break  # Don't count multiple times from the same category

        # Medium-risk keywords
        for keyword, (points, description) in PATH_MEDIUM_RISK_KEYWORDS.items():
            if keyword in path_lower:
                score += points
                findings.append(f"ℹ️ '{keyword}' detected in Path — {description} (+{points} points)")

        # URL encoding suspicion (excessively encoded characters)
        encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', path))
        if encoded_count >= 3:
            score += 8
            findings.append(f"⚠️ {encoded_count} URL-encoded characters in Path — suspected obfuscation (+8 points)")

        # Very deep path (7+ levels)
        depth = len([p for p in path.split('/') if p])
        if depth >= 7:
            score += 5
            findings.append(f"ℹ️ Very deep path ({depth} levels) — might be a hiding technique (+5 points)")

        return min(score, 35), findings  # Max 35 points from Path

    def _analyze_query(self, query_string: str) -> Tuple[int, List[str]]:
        """
        Analyzes the query string.
        Returns: (total score, list of findings)
        """
        if not query_string:
            return 0, []

        score = 0
        findings = []
        params = parse_qs(query_string, keep_blank_values=True)
        param_keys_lower = {k.lower() for k in params.keys()}

        # Redirection parameters
        redirect_found = param_keys_lower & REDIRECT_PARAMS
        if redirect_found:
            # Does the redirect value itself contain a domain?
            for key in params:
                if key.lower() in REDIRECT_PARAMS:
                    val = unquote(params[key][0]) if params[key] else ""
                    # Is the value a domain/URL?
                    if re.search(r'[a-z0-9\-]+\.[a-z]{2,}', val, re.IGNORECASE):
                        score += 20
                        findings.append(
                            f"🚨 Open Redirect: "
                            f"`?{key}={val}` — redirects user to another site (+20 points)"
                        )
                    else:
                        score += 8
                        findings.append(
                            f"⚠️ Redirection parameter detected: `?{key}=` (+8 points)"
                        )
                    break

        # Too many query parameters
        if len(params) >= 6:
            score += 5
            findings.append(f"ℹ️ {len(params)} query parameters — anomalous complexity (+5 points)")

        # URL encoding in Query
        encoded_count = len(re.findall(r'%[0-9A-Fa-f]{2}', query_string))
        if encoded_count >= 5:
            score += 7
            findings.append(f"⚠️ Heavy URL encoding in query string ({encoded_count} characters) (+7 points)")

        return min(score, 30), findings  # Max 30 points from Query

    def _analyze_host(self, host: str) -> Tuple[int, List[str]]:
        """
        Analyzes the host part (subdomain structure, brand impersonation).
        Returns: (total score, list of findings)
        """
        score = 0
        findings = []
        host_lower = host.lower()

        # Is an IP address being used?
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            score += 20
            findings.append("🚨 IP address used instead of domain — suspicious hosting (+20 points)")
            return score, findings

        parts = host_lower.split(".")

        # Too many subdomain levels (3+)
        subdomain_depth = len(parts) - 2  # Excluding TLD and main domain
        if subdomain_depth >= 3:
            score += 10
            findings.append(f"⚠️ {subdomain_depth}-level subdomain — complex structure (+10 points)")
        elif subdomain_depth == 2:
            score += 5
            findings.append(f"ℹ️ 2-level subdomain (+5 points)")

        # Brand impersonation detection
        # Example: paypal.security-update.tk → "paypal" in subdomain, but TLD is .tk
        host_without_tld = ".".join(parts[:-1]) if len(parts) > 1 else host_lower
        for brand in BRAND_DOMAINS:
            if brand in host_without_tld:
                # Is it the real brand domain? (paypal.com, google.com etc.)
                is_real = host_lower in (f"{brand}.com", f"www.{brand}.com",
                                          f"{brand}.net", f"{brand}.org")
                if not is_real:
                    score += 25
                    findings.append(
                        f"🚨 Brand impersonation: the word `{brand}` is in the subdomain/domain "
                        f"but it is not the real {brand}.com (+25 points)"
                    )
                    break

        # Excess hyphens (-) in domain (like google-security-update.com)
        main_domain = parts[-2] if len(parts) >= 2 else host_lower
        dash_count = main_domain.count("-")
        if dash_count >= 2:
            score += 8
            findings.append(f"⚠️ {dash_count} hyphens in domain — phishing pattern (+8 points)")
        elif dash_count == 1:
            score += 3
            findings.append(f"ℹ️ Hyphen used in domain (+3 points)")

        return min(score, 40), findings  # Max 40 points from Host

    def analyze(self, raw_url: str) -> Dict:
        """
        Main analysis function. Takes raw URL, returns full report.
        
        Returns:
        {
            "original_url":     str,    # The entered raw URL
            "normalized_url":   str,    # Normalized URL
            "extracted_domain": str,    # Domain to be fed into ML model
            "components": {             # Parsed components
                "scheme":    str,
                "host":      str,
                "path":      str,
                "query":     str,
                "fragment":  str,
                "params":    dict,      # Query param dictionary
            },
            "url_risk_boost":   int,    # Additional risk score between 0-50
            "risk_level":       str,    # "LOW" / "MEDIUM" / "HIGH" / "CRITICAL"
            "findings":         list,   # List of detected findings
            "summary":          str,    # Short summary
        }
        """
        # 1. Normalize
        normalized = self.normalize_url(raw_url)
        extracted_domain = self.extract_domain_from_url(raw_url)

        # 2. Parse
        try:
            parsed = urlparse(normalized)
            components = {
                "scheme":   parsed.scheme,
                "host":     parsed.netloc.lower(),
                "path":     parsed.path,
                "query":    parsed.query,
                "fragment": parsed.fragment,
                "params":   {k: v[0] for k, v in parse_qs(parsed.query).items()}
            }
        except Exception as e:
            return {
                "original_url": raw_url,
                "normalized_url": normalized,
                "extracted_domain": extracted_domain,
                "components": {},
                "url_risk_boost": 0,
                "risk_level": "UNKNOWN",
                "findings": [f"Could not parse URL: {e}"],
                "summary": "URL analysis failed."
            }

        # 3. Analyze components
        host_score, host_findings     = self._analyze_host(components["host"])
        path_score, path_findings     = self._analyze_path(components["path"])
        query_score, query_findings   = self._analyze_query(components["query"])

        all_findings = host_findings + path_findings + query_findings

        # HTTP (unencrypted) connection — small additional score
        if components["scheme"] == "http":
            http_bonus = 5
            all_findings.append("ℹ️ HTTP being used (unencrypted connection) (+5 points)")
        else:
            http_bonus = 0

        # 4. Total URL boost (max 50)
        total_boost = min(50, host_score + path_score + query_score + http_bonus)

        # 5. Risk level
        if total_boost >= 35:
            risk_level = "CRITICAL"
        elif total_boost >= 20:
            risk_level = "HIGH"
        elif total_boost >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 6. Generate summary
        if not all_findings:
            summary = "No obvious phishing indicators detected in URL structure."
        else:
            summary = (
                f"Detected {len(all_findings)} suspicious indicators during URL analysis. "
                f"The URL structure carries a {risk_level} risk level (+{total_boost} points added)."
            )

        return {
            "original_url":     raw_url,
            "normalized_url":   normalized,
            "extracted_domain": extracted_domain,
            "components":       components,
            "url_risk_boost":   total_boost,
            "risk_level":       risk_level,
            "findings":         all_findings,
            "summary":          summary,
        }

    def is_url(self, text: str) -> bool:
        """
        Determines if the given text is a domain or a full URL.
        Used in the Slack bot.
        """
        text = text.strip()
        normalized = self.normalize_url(text)
        try:
            parsed = urlparse(normalized)
            # Considered a URL if there is a path or query
            return bool(parsed.path and parsed.path != "/") or bool(parsed.query)
        except:
            return False


# =============================================================================
# SINGLETON
# =============================================================================
url_parser = URLParser()