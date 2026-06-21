# ChatSecOps: A Hybrid SOAR Framework for Automated Threat Analysis Using Explainable AI and Large Language Models

> **Şevval AYDOĞAN** · **Seray ÜSTÜN**  
> Department of Computer Engineering, Faculty of Engineering and Natural Sciences, Üsküdar University, Istanbul, Turkey  

---

## Abstract

Security Operations Centers face critical challenges from malicious domains used in phishing and command-and-control infrastructure. This study presents **ChatSecOps**, a hybrid Security Orchestration, Automation, and Response (SOAR) framework integrating machine learning, multi-source threat intelligence, and explainable AI. The system employs a LightGBM classifier trained on **284 features** from **90,000 domains**, achieving **99.75% accuracy** with **0.69 seconds training time**. Three-month pilot deployment resulted in **47% improvement in detection speed** and **31% reduction in false positive escalations**, successfully identifying zero-day threats such as `inetserv.pl` where traditional databases failed.

---

## Implementation Status

| Component | Status | Tested |
|---|---|---|
| LightGBM Classifier + SHAP XAI | ✅ Implemented | ✅ |
| Multi-source Threat Intelligence | ✅ Implemented | ✅ |
| Gemini AI Report Generation | ✅ Implemented | ✅ |
| Slack Bot Interface | ✅ Implemented | ✅ |
| SQLite Threat Memory | ✅ Implemented | ✅ |
| **Feature 1** — Phishing URL Parser | ✅ Implemented | ✅ |
| **Feature 2** — IOC Pivot Chain | ✅ Implemented | ✅ |
| **Feature 4** — NL Query Interface | ✅ Implemented | ✅ |
| **Feature 5** — MITRE ATT&CK Mapper | ✅ Implemented | ✅ |

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Components](#2-components)
3. [Repository Structure](#3-repository-structure)
4. [Prerequisites & API Keys](#4-prerequisites--api-keys)
5. [Installation](#5-installation)
6. [Environment Variables](#6-environment-variables)
7. [Running the System](#7-running-the-system)
8. [API Reference](#8-api-reference)
9. [Slack Commands](#9-slack-commands)
10. [Machine Learning Model](#10-machine-learning-model)
11. [Experimental Results](#11-experimental-results)
12. [Dataset](#12-dataset)
13. [Replication Guide](#13-replication-guide)
14. [Troubleshooting](#14-troubleshooting)
15. [Authors & Citation](#15-authors--citation)

---

## 1. System Architecture

ChatSecOps consists of five architectural layers: user interface, orchestration, intelligence fusion, analysis engines, and output generation.

```
┌─────────────────────────────────────────────────────────────┐
│                    Slack Interface                           │
│              (slack_bot.py — Bolt Framework)                 │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP
┌───────────────────────▼─────────────────────────────────────┐
│               FastAPI Orchestration Layer                    │
│                      (main.py)                              │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  LightGBM    │  │  Phishing    │  │  Natural Language │  │
│  │  Classifier  │  │  URL Parser  │  │  Query Engine     │  │
│  │  + SHAP XAI  │  │  (Feature 1) │  │  (Feature 4)      │  │
│  └──────┬───────┘  └──────────────┘  └───────────────────┘  │
│         │                                                    │
│  ┌──────▼───────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │  Intelligence│  │  Pivot       │  │  MITRE ATT&CK     │  │
│  │  Fusion      │  │  Engine      │  │  Taxonomic Mapper │  │
│  │  VT/IPDB/OTX │  │  (Feature 2) │  │  (Feature 5)      │  │
│  │  /Shodan     │  └──────────────┘  └───────────────────┘  │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────┐
│                   SQLite Database (WAL mode)                 │
│  domain_analysis | ip_clusters | domain_similarity |         │
│  threat_campaigns                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Components

### Intelligence Fusion Layer

Aggregates threat intelligence from four external sources in parallel API calls with timeout limits:

| Source | Data Provided |
|---|---|
| VirusTotal | Domain reputation across 92 antivirus engines |
| AbuseIPDB | IP abuse confidence score and historical reports |
| AlienVault OTX | Open Threat Exchange pulse indicators |
| Shodan | Open ports, CVE vulnerabilities, ASN data |
| URLhaus | Malware URL database lookup |
| ThreatFox | IOC database lookup |

---

### Feature 1: Heuristic Phishing URL Decomposition Engine
**File:** `ChatSecOps_URLParser.py`

Traditional ML classifiers operate on root domain traits only, missing signals in path and query parameters. This engine adds a rule-based scoring layer on top of the ML score.

**Final score formula (Eq. 6 from paper):**
```
Tfinal = min(100, MLGBM + Rboost)
```

Where:
```
Rboost = min(50, f(H) + g(P) + h(Q) + δhttp)        (Eq. 2)

f(H) = min(40, 25·brand_impersonation + 10·subdomain_depth≥3 + 8·dashes≥2)
g(P) = min(35, Σ keyword_weights + 8·obfuscation + 5·depth≥7)
h(Q) = min(30, 20·open_redirect + 7·heavy_encoding)
δhttp = 5 (penalty for unencrypted HTTP)
```

**Scoring rules:**

| Component | Signal | Points |
|---|---|---|
| Host | Brand impersonation in subdomain | +25 |
| Host | 3+ subdomain depth | +10 |
| Host | 2+ hyphens in domain | +8 |
| Path | `/login`, `/signin`, `/verify` | +15 |
| Path | `/secure`, `/security`, `/update` | +12 |
| Path | URL-encoded chars ≥ 3 | +8 |
| Query | Open redirect to external domain | +20 |
| Query | Redirect parameter present | +8 |
| Scheme | HTTP (unencrypted) | +5 |

**Defanged URL support:** Automatically normalizes `hxxps://`, `[.]`, `[:]` notation.

**Tested output** (`analyze hxxps://paypal-security.tk/login?redirect=paypal.com`):
```
URL Yapısal Analizi
Kombine Skor: 50.0% (CRITICAL) | URL Risk Seviyesi: CRITICAL
Bulgular:
  🚨 Marka taklidi: paypal kelimesi subdomain'de var ama paypal.com değil (+25)
  ⚠️  Domain'de tire kullanımı (+3)
  ⚠️  Path'te 'login' tespit edildi — oturum açma sayfası taklidi (+15)
  🚨 Açık yönlendirme (Open Redirect): ?redirect=paypal.com (+20)
```

---

### Feature 2: Pivot Engine (IOC Chain Analysis)
**File:** `ChatSecOps_Pivot.py`

Performs automatic infrastructure pivoting on the resolved IP, discovering co-hosted domains via two channels: local threat memory and Shodan real-time hostname enumeration.

**Processing delay model (Eq. 7 from paper):**
```
Ttotal = Σ(Tinfer(di) + Tenrich(di)) + min(N, K) · Δt
```
Where K = 5 (PIVOT_MAX_DEPTH), Δt = 2s (PIVOT_DELAY).

**Loop protection:** `already_analyzed` set prevents revisiting nodes; depth capped at 5.

**Automatic trigger:** Runs after every domain analysis when IP is resolved.

**Manual trigger:** `GET /pivot/{domain}`

**Slack output example:**
```
🕸️ Pivot Zinciri: Bu IP üzerinde 4 ilişkili domain tespit edildi.
2 yeni domain otomatik analiz edildi.

📁 Veritabanımızda Bu IP'de Görülen Domainler:
  🔴 fake-bank.tk — Risk: 91% | Son görülme: 2026-05-12
  🔴 phish-paypal.ru — Risk: 87% | Son görülme: 2026-05-30

🚨 KAMPANYA UYARISI: Koordineli saldırı kampanyası olabilir.
```

> ⚠️ **Note:** Pivot engine requires a resolved IP address. If the domain cannot be resolved (IP: N/A), pivot is skipped automatically.

---

### Feature 4: Natural Language Query Engine (Text-to-SQL)
**File:** `ChatSecOps_NLQuery.py`

Provides secure database querying using plain language via Slack. No SQL knowledge required.

**Pipeline:** `User question → Gemini (schema context) → SQL → SQLite → Gemini (format) → Answer`

**Safety verification (Eq. 8 from paper):**
```
V(Q) = 1{Prefix(Q)="SELECT"} ∧ ∏ 1{k∉Qtokens}
```
Where Kforbidden = {INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE}.

**Tested output:**
```
query Kaç domain analiz edildi?

→ 🤖 SOC Asistanı
  Analiz edilen toplam domain sayısı 6 olarak tespit edilmiştir.
  📌 1 kayıt üzerinden analiz yapıldı
```

**Supported query examples:**
```
query How many malicious domains were detected this week?
query What are the top 5 riskiest domains?
query Which countries do threats come from?
query Which TLDs are most associated with malware?
query Show domains sharing a high-risk IP cluster
```

---

### Feature 5: MITRE ATT&CK Taxonomic Mapping Engine
**File:** `ChatSecOps_MITRE.py`

Deterministic mapping from SHAP feature attributions, URL parser findings, and Shodan data to official MITRE ATT&CK technique IDs. Results embedded in Slack notifications.

**Mapping logic (from paper Section 3.7):**

| Technique | Trigger Condition |
|---|---|
| **T1566.002** Spearphishing Link | URL engine flags brand impersonation, `/login` path, or open-redirect |
| **T1568.002** Domain Generation Algorithms | Top SHAP features show high Entropy or anomalous character distribution |
| **T1071.001** Web Protocols C2 | Shodan finds C2 ports or CVEs; Pivot finds shared malicious infrastructure |
| **T1583.001** Acquire Infrastructure: Domains | CreationDate top SHAP feature; free/abused TLD (.tk, .ml) detected |
| **T1598.003** Phishing for Information | T1566.002 triggered AND open redirect or missing SPF |
| **T1190** Exploit Public-Facing Application | Shodan CVEs found + ML risk ≥ 60% |

**Tested output** (`analyze hxxps://paypal-security.tk/login?redirect=paypal.com`):
```
🛡️ MITRE ATT&CK Taxonomic Mapping
3 Techniques Identified | Primary Tactic: Initial Access

🔴 T1566.002 — Phishing: Spearphishing Link
🚪 Tactic: Initial Access  |  Confidence: High Confidence
  › brand impersonation detected in subdomain
  › high-risk login/verify path in URL
  › open redirect query chain detected

🟠 T1583.001 — Acquire Infrastructure: Domains
🏗️ Tactic: Resource Development  |  Confidence: Medium Confidence
  › Free/abused TLD '.tk' — documented high abuse rate (>40%)

🟠 T1598.003 — Phishing for Information: Spearphishing Link
🔭 Tactic: Reconnaissance  |  Confidence: Medium Confidence
  › Open redirect to harvest credentials from spoofed landing page

📌 Tactics Covered: 🚪 Initial Access · 🏗️ Resource Development · 🔭 Reconnaissance
```

---

## 3. Repository Structure

```
ChatSecOps/
│
├── main.py                          # FastAPI backend — orchestration engine
├── slack_bot.py                     # Slack bot — Bolt framework
│
├── ChatSecOps_Intelligence.py       # Threat intelligence (VT, AbuseIPDB, OTX, Shodan)
├── ChatSecOps_Memory.py             # SQLite persistence + campaign detection
├── ChatSecOps_Analytics.py          # PDF forensic report generation
├── xai_explainer.py                 # SHAP TreeExplainer integration
│
├── ChatSecOps_URLParser.py          # [Feature 1] Phishing URL decomposition engine
├── ChatSecOps_Pivot.py              # [Feature 2] IOC pivot chain engine
├── ChatSecOps_NLQuery.py            # [Feature 4] Natural language Text-to-SQL engine
├── ChatSecOps_MITRE.py              # [Feature 5] MITRE ATT&CK taxonomic mapper
│
├── model_outputs/
│   ├── chatsecops_model_v2_20260114_203833.joblib          # Trained LightGBM model
│   ├── chatsecops_model_v2_20260114_203833_scaler.joblib   # StandardScaler
│   └── chatsecops_model_v2_20260114_203833_metadata.json   # Feature names, TLD list, config
│
├── chatsecops_memory.db             # SQLite database (auto-created on first run)
├── .env                             # API keys (never commit this file)
├── requirements.txt                 # Python dependencies
└── README.md
```

---

## 4. Prerequisites & API Keys

**Python 3.9+** required.

| API Key | Service | Free Tier Limit | Obtain From |
|---|---|---|---|
| `GEMINI_API_KEY` | Google Gemini 2.5 Flash | Daily quota | [aistudio.google.com](https://aistudio.google.com) → Get API Key |
| `VIRUSTOTAL_API_KEY` | 92 AV engines | 4 req/min | [virustotal.com](https://www.virustotal.com) → Profile → API Key |
| `ABUSEIPDB_API_KEY` | IP abuse scores | 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com) → Account → API |
| `ALIENVAULT_API_KEY` | OTX threat pulses | Unlimited | [otx.alienvault.com](https://otx.alienvault.com) → Settings → API Key |
| `SHODAN_API_KEY` | Ports, CVEs, hostnames | Limited free | [account.shodan.io](https://account.shodan.io) |
| `IPINFO_TOKEN` | IP geolocation | 50,000 req/month | [ipinfo.io/account/token](https://ipinfo.io/account/token) |
| `SLACK_BOT_TOKEN` | Slack bot | Free | [api.slack.com/apps](https://api.slack.com/apps) |
| `SLACK_APP_TOKEN` | Socket Mode | Free | [api.slack.com/apps](https://api.slack.com/apps) → App-Level Tokens |

---

## 5. Installation

```bash
# 1. Clone
git clone https://github.com/sevvallaydogann/ChatSecOps.git
cd ChatSecOps

# 2. Virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# 3. Dependencies
pip install -r requirements.txt
```

If `requirements.txt` is missing:

```bash
pip install fastapi uvicorn slack-bolt python-dotenv \
            lightgbm scikit-learn pandas numpy joblib \
            google-generativeai requests python-whois \
            dnspython ipinfo shodan shap matplotlib \
            reportlab pillow
```

### Slack App Setup

1. [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From Scratch**
2. **OAuth & Permissions** → Bot Token Scopes: `chat:write`, `files:write`, `channels:history`, `im:history`, `channels:read`
3. **Install App** to workspace → copy **Bot User OAuth Token** → `SLACK_BOT_TOKEN`
4. **Basic Information** → **App-Level Tokens** → Generate with `connections:write` scope → `SLACK_APP_TOKEN`
5. **Socket Mode** → Enable

---

## 6. Environment Variables

Create `.env` in the project root:

```env
# Slack
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token

# AI
GEMINI_API_KEY=your-gemini-key

# Threat Intelligence
VIRUSTOTAL_API_KEY=your-vt-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
ALIENVAULT_API_KEY=your-otx-key
SHODAN_API_KEY=your-shodan-key
IPINFO_TOKEN=your-ipinfo-token

# Backend
BACKEND_API_URL=http://localhost:8000

# Optional: for pivot Slack notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
```

---

## 7. Running the System

Two terminals required simultaneously.

**Terminal 1 — FastAPI backend:**
```bash
uvicorn main:app --reload --port 8000
```

Expected startup:
```
✅ [GEMINI] Model yüklendi: models/gemini-1.5-flash-latest
✅ [INTEL] Shodan Hazır.
INFO: Application startup complete.
INFO: Uvicorn running on http://127.0.0.1:8000
```

**Terminal 2 — Slack bot:**
```bash
python slack_bot.py
```

Expected:
```
🚀 ChatSecOps Slack Bot (Hybrid v5.0) is starting...
⚡️ Bolt app is running!
```

Interactive API docs: `http://localhost:8000/docs`

---

## 8. API Reference

### `GET /enrich-and-summarize/domain/{domain}`
Full domain analysis pipeline (ML + SHAP + 4 threat feeds + Gemini + Pivot + MITRE).
```
GET /enrich-and-summarize/domain/example.com
```

### `GET /analyze-url` *(Feature 1)*
Full URL structural decomposition + domain analysis + MITRE mapping.
```
GET /analyze-url?url=hxxps://paypal-security.tk/login?redirect=paypal.com
```

Additional response fields:
```json
{
  "url_analysis": {
    "url_risk_boost": 50,
    "url_risk_level": "CRITICAL",
    "findings": ["🚨 Brand impersonation...", "⚠️ /login in path..."]
  },
  "combined_score": "50.0%",
  "combined_verdict": "CRITICAL",
  "mitre_attack": {
    "total_triggered": 3,
    "techniques": [
      {"technique_id": "T1566.002", "confidence": "HIGH", ...},
      {"technique_id": "T1583.001", "confidence": "MEDIUM", ...},
      {"technique_id": "T1598.003", "confidence": "MEDIUM", ...}
    ]
  }
}
```

### `GET /pivot/{domain}` *(Feature 2)*
Manual IOC pivot chain trigger.
```
GET /pivot/malicious-domain.tk
```

### `GET /agent/ask` *(Feature 4)*
Natural language database query.
```
GET /agent/ask?query=How many malicious domains in the last 7 days?
```

### `GET /statistics`
Aggregated system statistics.

---

## 9. Slack Commands

Invite the bot: `/invite @ChatSecOps`

| Command | Description |
|---|---|
| `analyze <domain>` | Full security scan — ML + SHAP + 4 feeds + Gemini + Pivot + MITRE |
| `analyze <full_url>` | URL decomposition analysis (Feature 1) + MITRE mapping (Feature 5) |
| `check <domain>` | Same as analyze |
| `scan <domain>` | Same as analyze |
| `query <question>` | Natural language DB query (Feature 4) |
| `ask <question>` | Same as query |
| `stats` | System threat statistics |
| `status` | API health check |
| `help` | Command menu |

**Supported defanged URL formats:**
```
analyze hxxps://evil.tk/login
analyze hxxp://evil.tk/path
analyze evil.tk/login?redirect=paypal.com
analyze evil[.]tk/verify
```

**Example query commands:**
```
query Kaç domain analiz edildi?
query Son 7 günde kaç zararlı domain var?
query En riskli 5 domain hangisi?
query Hangi ülkelerden tehdit geliyor?
query En çok hangi TLD zararlı?
```

---

## 10. Machine Learning Model

### Training Configuration

| Parameter | Value |
|---|---|
| Algorithm | LightGBM (Gradient Boosted Decision Trees) |
| Training samples | 72,000 (80% of 90,000) |
| Test samples | 18,000 (20% stratified) |
| Cross-validation | 5-fold on training set |
| CV accuracy variance | < 0.3% across folds |
| Classification threshold | P(Malicious\|X) ≥ 0.70 |

**Inference function:**
```
P(Malicious | X) = 1 / (1 + e^(−Σwᵢxᵢ))
```

### IP Resolution Strategy (4-layer fallback)
1. Standard socket resolution
2. DNS library via Google DNS (8.8.8.8)
3. Cloudflare DNS-over-HTTPS
4. Google DNS-over-HTTPS

### Feature Categories (284 total)

**Lexical (40):** `DomainLength`, `Entropy` (Shannon), `NumericRatio`, `VowelRatio`, `ConsonantRatio`, `SpecialCharRatio`, `NumDots`, `NumHyphens`

**Structural:** TLD classification (top 30 one-hot encoded), `SubdomainNumber`, URL depth

**Network:** `CountryCode`, `ASN`, `IPRangeClass`

**DNS Security:** `HasSPFInfo`, `HasDkimInfo`, `HasDmarcInfo`, MX/TXT validation

**WHOIS:** `CreationDate` (domain age), `DaysSinceLastUpdate`, `RegisteredCountry`

### Top SHAP Features

| Rank | Feature | Mean \|SHAP\| | Interpretation |
|---|---|---|---|
| 1 | Entropy | 3.20 | DGA / random string indicator |
| 2 | TLD_Grouped_tk | 2.80 | Free TLD, >40% documented abuse |
| 3 | TLD_Grouped_ml | 2.40 | Free TLD, >40% documented abuse |
| 4 | HasSPFInfo | 2.10 | Absence = no legitimate email infra |
| 5 | CreationDate | 1.90 | 78% malicious domains registered < 30 days |

---

## 11. Experimental Results

### Model Performance Comparison

| Model | Accuracy | Precision | Recall | F1-Score | Training Time |
|---|---|---|---|---|---|
| Logistic Regression | 99.38% | 99.70% | 99.06% | 99.38% | 4.49s |
| Random Forest | 99.61% | 99.88% | 99.33% | 99.60% | 1.75s |
| Gradient Boosting | **99.77%** | **99.87%** | **99.68%** | **99.77%** | 64.71s |
| **ChatSecOps LightGBM** | **99.75%** | 99.82% | **99.68%** | 99.75% | **0.69s** |
| XGBoost | ~99.7% | — | — | — | 3.62s |

LightGBM achieves **93× faster training** than Gradient Boosting (ROC-AUC: 1.0000).

### Confusion Matrix (18,000 test samples)

```
                   Predicted Benign    Predicted Malicious
True Benign             8,980                  20         → FPR: 0.22%
True Malicious             25               8,975         → FNR: 0.28%
```

### System Latency (100 production queries)

| Component | Median |
|---|---|
| ML inference | 0.15s |
| External API calls (parallel) | 3.2s |
| Gemini synthesis | 2.1s |
| **Total end-to-end** | **5.8s** (95th pct: 12.3s) |

Throughput: **150+ domains/hour** on a single 4-core server.

### Case Study: inetserv.pl (Zero-Day Detection)

| Detection Platform | Result |
|---|---|
| VirusTotal API | 0/95 vendor flags (Clean) |
| AbuseIPDB | 0% Abuse Confidence (Safe) |
| **ChatSecOps LightGBM** | **95.3% Malicious Risk** |

Pivot Engine subsequently discovered 4 additional subdomains under the same ASN.

### Pilot Deployment (3 months, 12,000 domains)

| Metric | Result |
|---|---|
| Mean time to detect improvement | **47% faster** vs. manual triage |
| False positive escalation reduction | **31% reduction** |
| Mean time to analyze | 25 seconds (vs. 15 minutes manual) |
| Analyst satisfaction | 8.7/10 (baseline: 6.2/10) |
| Gemini report positive feedback | 92% |

---

## 12. Dataset

> Marques C. **Benign and malicious domains based on DNS logs** (Version 5).  
> Mendeley Data, 2021.  
> https://data.mendeley.com/datasets/623sshkdrz/5  
> doi: 10.17632/623sshkdrz.5

- **90,000 total samples** — 45,000 benign, 45,000 malicious (balanced)
- Preprocessing: one-hot encoding for DNS types/country codes/TLDs, StandardScaler for numeric features
- Train/test split: 80/20 stratified

---

## 13. Replication Guide

### Step 1: Clone and install
```bash
git clone https://github.com/sevvallaydogann/ChatSecOps.git
cd ChatSecOps
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: API Keys
Minimum required: `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`

### Step 3: Create `.env` (see Section 6)

### Step 4: Verify model files
```bash
python3 -c "
import joblib, json
model = joblib.load('model_outputs/chatsecops_model_v2_20260114_203833.joblib')
with open('model_outputs/chatsecops_model_v2_20260114_203833_metadata.json') as f:
    meta = json.load(f)
print(f'Model: {type(model).__name__}')
print(f'Features: {len(meta[\"dataset_info\"][\"feature_names\"])} features')
"
```

Expected:
```
Model: LGBMClassifier
Features: 284 features
```

### Step 5: Start services
```bash
# Terminal 1
uvicorn main:app --reload --port 8000

# Terminal 2
python slack_bot.py
```

### Step 6: Validation test sequence

```
# Slack:
help
analyze google.com
analyze hxxps://paypal-security.tk/login?redirect=paypal.com
query Kaç domain analiz edildi?
query En riskli 5 domain hangisi?
```

### Expected results

| Test | Expected |
|---|---|
| `analyze google.com` | SAFE (0-15%) |
| `analyze hxxps://paypal-security.tk/login?redirect=paypal.com` | CRITICAL + URL findings + 3 MITRE techniques |
| `query` commands | SQL-backed natural language answer |

---

## 14. Troubleshooting

### `❌ [KRİTİK HATA] Metadata yüklenemedi`
Model files missing from `model_outputs/`. Verify all three files (`.joblib` ×2, `.json`) are present.

### `Gemini quota exhausted (429)`
Daily free quota used up.
- Create new key at [aistudio.google.com](https://aistudio.google.com) (resets immediately)
- System falls back to rule-based report generator automatically

### `IP Address: N/A` for all domains
Usually caused by Gemini quota exhaustion (prevents full pipeline execution). Fix Gemini key first.

Diagnose DNS separately:
```bash
python3 -c "import socket; print(socket.gethostbyname('google.com'))"
```

### Pivot chain not triggering
Pivot requires a resolved IP (`IP Address` must not be N/A). Fix the Gemini/DNS issue first.

### MITRE block not appearing in Slack
Ensure `ChatSecOps_MITRE.py` is in the project folder and both `main.py` and `slack_bot.py` have `from ChatSecOps_MITRE import mitre_mapper` imported.

### `invalid_auth` Slack error
`SLACK_BOT_TOKEN` expired. Reinstall the app in your workspace.

### Port 8000 already in use
```bash
lsof -i :8000 && kill -9 <PID>
uvicorn main:app --reload --port 8000
```

---

## 15. Authors 

### Authors

| Name | ORCID | Student ID | Email |
|---|---|---|---|
| **Şevval AYDOĞAN** | [0009-0006-0806-2654](https://orcid.org/0009-0006-0806-2654) | 210201045 | sevval.aydogan@st.uskudar.edu.tr |
| **Seray ÜSTÜN** | [0009-0008-0918-9395](https://orcid.org/0009-0008-0918-9395) | 210201063 | seray.ustun@st.uskudar.edu.tr |

Department of Computer Engineering, Faculty of Engineering and Natural Sciences  
**Üsküdar University**, Istanbul, Turkey

### Acknowledgments

The authors thank the open-source community for Slack Bolt, scikit-learn, SHAP, LightGBM, FastAPI, and Google Gemini.

### Declaration of Generative AI

During preparation of this work, the authors used Google Gemini 2.5 Flash to synthesize technical threat intelligence data within the proposed system architecture. All AI-generated content was manually reviewed and validated against source intelligence feeds.

### Data Availability

Dataset: Marques C. Benign and malicious domains based on DNS logs (Version 5). https://data.mendeley.com/datasets/623sshkdrz/5

