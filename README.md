# ChatSecOps
### A Hybrid SOAR Framework for Automated Threat Analysis Using Explainable AI and Large Language Models

> Graduation Project — Şevval Aydoğan & Seray Üstün  
> Department of Computer Engineering, Uskudar University, 2026

---

## What is this?

Security Operations Centers deal with hundreds of alerts every day, and most of that initial triage work — checking domains, pulling threat intel, writing up findings — is repetitive and slow. ChatSecOps is our attempt to automate that.

The system takes a suspicious domain or IP, runs it through a trained ML classifier, pulls threat data from multiple intelligence sources, and delivers a plain-language security report directly in Slack — all in about 25 seconds, compared to the ~15 minutes a manual analysis would take.

---

## How it works

**Machine Learning Core**  
A LightGBM classifier trained on 90,000 domains (45k benign, 45k malicious) extracts 284 features covering lexical patterns, DNS records, network infrastructure, and WHOIS data. It achieves 99.75% accuracy with a training time of 0.69 seconds, which means the model can be retrained regularly as the threat landscape evolves.

**Explainability (SHAP)**  
Each prediction is accompanied by a SHAP waterfall visualization that highlights the key features influencing the model’s decision. This enables analysts to understand not only *what* was predicted, but also *why* it was predicted.

**Threat Intelligence Fusion**  
The system queries four sources in parallel:
- VirusTotal (92 AV engine consensus)
- AbuseIPDB (IP abuse history)
- AlienVault OTX (community threat pulses)
- Shodan (open ports, CVE associations)

**AI Report Generation**  
Google Gemini 2.5 Flash synthesizes everything into a structured executive summary with a MALICIOUS / SUSPICIOUS / SAFE verdict and recommended actions. When the Gemini API is unavailable, a rule-based fallback generator keeps things running.

**Threat Memory**  
A SQLite database tracks analysis history and flags patterns like campaign detection (multiple malicious domains with the same TLD in a 7-day window), typosquatting (domains >70% similar to known ones), and shared IP clustering.

---

## Results

| Metric | Value |
|---|---|
| Accuracy | 99.75% |
| Precision | 99.82% |
| Recall | 99.68% |
| F1-Score | 99.75% |
| False Positive Rate | 0.22% |
| False Negative Rate | 0.28% |
| Mean Time to Analyze | ~25 seconds (was 15 min) |
| Detection Speed Improvement | 47% |
| False Positive Escalation Reduction | 31% |
| Zero-day threats identified | 43 |

---

## Top Predictive Features (SHAP)

1. **Entropy** — high randomness in character sequences indicates DGA-generated domains
2. **TLD (.tk, .ml)** — free TLDs with >40% documented abuse rates
3. **SPF / DKIM / DMARC absence** — missing email authentication is a strong malicious signal
4. **Domain creation date** — 78% of detected malicious domains were registered within 30 days
5. **Domain length** — malicious domains averaged 67 characters vs. 23 for legitimate ones

---

## Project Structure

```
├── ChatSecOps/
│   ├── main.py
│   ├── slack_bot.py
│   ├── ChatSecOps_Intelligence.py
│   ├── ChatSecOps_Memory.py
│   ├── ChatSecOps_Analytics.py
│   ├── ChatSecOps_Figure_generator.py
│   ├── xai_explainer.py
│   ├── data_model.ipynb
│   ├── checkmodels.py
│   ├── .gitignore
│   ├── test_api.py
│   ├── debug_ogx.py
│   └── requirements.txt
├── Report_Figures/
│   ├── fig2_confusion_matrix.pdf
│   ├── fig3_shap_summary.pdf
│   ├── fig4_performance_consolidated.pdf
│   ├── slack_bigbins_malicious.pdf
│   ├── slack_google_safe.pdf
│   ├── slack_ip_critical.pdf
│   └── slack_pbiaas_conflict.pdf
├── Final_Report.pdf
└── README.md
```

---

## Setup

**1. Clone and install dependencies**
```bash
git clone https://github.com/sevvallaydogann/ChatSecOps.git
cd ChatSecOps
pip install -r ChatSecOps/requirements.txt
```

**2. Set up environment variables**

Create a `.env` file in the root directory:
```
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
OTX_API_KEY=your_key
SHODAN_API_KEY=your_key
GEMINI_API_KEY=your_key
SLACK_BOT_TOKEN=your_token
SLACK_APP_TOKEN=your_token
```

**3. Train the model**

Run `notebooks/data_model.ipynb` to generate the trained model files.

**4. Start the bot**
```bash
python ChatSecOps/main.py
```

---

## Dataset

The model was trained on a public dataset of benign and malicious domains based on DNS logs:

> Marques C. *Benign and malicious domains based on DNS logs* (Version 5). Mendeley Data, 2021.  
> https://data.mendeley.com/datasets/623sshkdrz/5

---

## Authors

**Şevval Aydoğan** — [ORCID](https://orcid.org/0009-0006-0806-2654) — sevval.aydogan@st.uskudar.edu.tr  
**Seray Üstün** — [ORCID](https://orcid.org/0009-0008-0918-9395) — seray.ustun@st.uskudar.edu.tr

Department of Computer Engineering, Uskudar University, Istanbul, Turkey
