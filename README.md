# ChatSecOps – Reproducibility README

This README explains how to run and reproduce the **ChatSecOps** project developed in the thesis study.

---

# 1. Project Overview

**ChatSecOps** is an AI-assisted cyber threat investigation platform developed for **malicious domain and URL analysis**.
The system combines:

* machine learning–based malicious domain classification,
* rule-based URL structural analysis,
* threat intelligence enrichment from external sources,
* MITRE ATT&CK mapping,
* IOC pivot analysis,
* a threat memory database for historical investigation tracking,
* SHAP/XAI-based explainability,
* automated PDF reporting,
* Slack-based analyst notifications,
* natural language querying over the stored threat investigation data.

The project was developed as part of the undergraduate thesis study.

---

# 2. Project Structure

The repository is organized as follows:

```bash id="7x90vw"
CHATSECOPS/
│
├── .env                               # API keys and environment variables
├── .gitignore
├── requirements.txt                   # Python dependencies
├── main.py                            # Main application entry point
├── slack_bot.py                       # Slack bot integration
│
├── ChatSecOps_Agent.py                # Autonomous AI investigation agent
├── ChatSecOps_Analytics.py            # Threat statistics / analytics logic
├── ChatSecOps_Figure_generator.py     # Figure / visualization generation utilities
├── ChatSecOps_Intelligence.py         # Threat intelligence integrations
├── ChatSecOps_Memory.py               # Threat memory / historical analysis logic
├── ChatSecOps_MITRE.py                # MITRE ATT&CK mapping module
├── ChatSecOps_NLQuery.py              # Natural language query interface
├── ChatSecOps_Pivot.py                # IOC pivot analysis module
├── ChatSecOps_URLParser.py            # URL structural analysis engine
├── xai_explainer.py                   # SHAP/XAI explanation generation
│
├── chatsecops_memory.db               # SQLite threat memory database
├── checkmodels.py                     # Model checking / validation script
├── test_api.py                        # API testing utility
├── debug_ogx.py                       # Debugging / experimental utility
├── data_model.ipynb                   # Notebook used during model development
├── chatsecops_tum_kodlar.txt          # Consolidated code / reference text file
│
├── model_outputs/                     # Saved ML model outputs / artifacts
├── Report_Figures/                    # Figures used in thesis/report
├── static/                            # Generated outputs (reports, graphs, assets)
```

---

# 3. System Requirements

The project was developed and tested in a Python environment on Windows.

## Recommended environment

* **Operating System:** Windows 10 / Windows 11
* **Python Version:** Python 3.10+
* **Package Manager:** pip
* **Recommended IDE:** Visual Studio Code

---

# 4. Installation

## 4.1 Open the project folder

Place the project folder in a working directory and open a terminal inside the `CHATSECOPS` folder.

## 4.2 Create a virtual environment (recommended)

```bash id="8b2hoh"
python -m venv venv
```

Activate it:

### Windows

```bash id="t30ej1"
venv\Scripts\activate
```

### Linux / macOS

```bash id="yjlwm7"
source venv/bin/activate
```

## 4.3 Install required packages

```bash id="j9d1gt"
pip install -r requirements.txt
```

---

# 5. Environment Variables and API Keys

The project uses multiple external services for cyber threat intelligence enrichment and AI-based summarization.
Create a `.env` file in the root directory and add the required API keys.

Example `.env` structure:

```env id="2n83aj"
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key
SHODAN_API_KEY=your_shodan_api_key
GEMINI_API_KEY=your_gemini_api_key
GROQ_API_KEY=your_groq_api_key

SLACK_BOT_TOKEN=your_slack_bot_token
SLACK_APP_TOKEN=your_slack_app_token
SLACK_SIGNING_SECRET=your_slack_signing_secret
SLACK_WEBHOOK_URL=your_slack_webhook_url
```

## Notes

* If some API keys are missing, the corresponding module may fail or be skipped.
* Core local components such as **URL parsing**, **database logic**, and **model-related modules** may still be tested independently depending on the configuration.

---

# 6. Main Components of the Project

## 6.1 `main.py`

This is the main application entry point of the ChatSecOps platform.
It coordinates the overall investigation flow and connects the different modules.

## 6.2 `ChatSecOps_Agent.py`

Implements the autonomous AI investigation agent.
The agent decides which threat intelligence tools to use, gathers evidence, and generates investigation summaries.

## 6.3 `ChatSecOps_URLParser.py`

Performs **rule-based URL structural analysis**.
It evaluates suspicious URL characteristics such as:

* IP-based URLs,
* suspicious subdomain structures,
* phishing-related keywords,
* risky paths,
* redirection indicators,
* suspicious query parameters,
* obfuscation patterns.

## 6.4 `ChatSecOps_Intelligence.py`

Handles integrations with external cyber threat intelligence services such as:

* VirusTotal
* AbuseIPDB
* AlienVault OTX
* Shodan

## 6.5 `ChatSecOps_MITRE.py`

Maps suspicious findings to relevant **MITRE ATT&CK tactics and techniques**.

## 6.6 `ChatSecOps_Pivot.py`

Performs **IOC pivot analysis** using IP-based relationships and historical investigation data.

## 6.7 `ChatSecOps_Memory.py`

Handles storage and retrieval of previously analysed domains / URLs using the local SQLite database (`chatsecops_memory.db`).

## 6.8 `ChatSecOps_NLQuery.py`

Supports natural language queries over the stored threat intelligence database, such as:

* top riskiest domains,
* number of malicious domains,
* country-based summaries,
* historical threat statistics.

## 6.9 `xai_explainer.py`

Generates **SHAP/XAI explanations** to interpret the machine learning model’s predictions.

## 6.10 `slack_bot.py`

Provides Slack integration for analyst interaction, command execution, and real-time notifications.

---

# 7. Running the Project

## 7.1 Run the main ChatSecOps application

Use the following command from the project root directory:

```bash id="q8bwtw"
python main.py
```

This launches the main application and enables the ChatSecOps investigation workflow.

---

# 8. Slack Bot Usage

If Slack integration and tokens are configured correctly, the system can be used through Slack commands.

## Example commands

```text id="y2r6ut"
analyze github.com
analyze https://grantexx.com/Tilsee.cur
analyze http://192.142.28.77/bachekuni/ohshit.mips
query Top 5 riskiest domains?
query How many malicious domains in the last 7 days?
query Which countries are threats coming from?
stats
status
```

## Expected Slack workflow

When an `analyze` command is submitted, the system may perform the following steps:

1. Parse the domain or URL
2. Run malicious domain / URL risk evaluation
3. Query threat intelligence feeds
4. Retrieve historical memory data
5. Perform IOC pivot analysis if needed
6. Map findings to MITRE ATT&CK
7. Generate an AI-based summary
8. Optionally generate a PDF report
9. Return the results through Slack

---

# 9. URL Analysis Reproduction

The project includes a rule-based **URL structural analysis engine** in `ChatSecOps_URLParser.py`.

This module can be used to evaluate suspicious URLs such as phishing URLs, impersonation URLs, or URLs containing risky path/query structures.

Example target:

```text id="w8q5gn"
http://192.142.28.77/bachekuni/ohshit.mips
```

The URL parser analyses:

* host structure,
* IP usage,
* suspicious keywords,
* subdomain complexity,
* path tokens,
* query patterns,
* possible redirection behaviour.

The output is used as part of the final risk assessment.

---

# 10. Threat Intelligence Enrichment

The threat intelligence module enriches investigated domains / URLs using external services.

The following sources may be queried depending on configuration and risk level:

* **VirusTotal**
* **AbuseIPDB**
* **AlienVault OTX**
* **Shodan**

The returned results are combined with local model outputs and URL findings to support the final verdict.

---

# 11. Threat Memory Database

ChatSecOps stores historical investigation results in the local SQLite database:

```text id="r3tv9v"
chatsecops_memory.db
```

This database is used to:

* store previously analysed domains / URLs,
* keep historical risk scores,
* support repeated investigation awareness,
* provide context for pivot analysis,
* support natural language database queries.

---

# 12. MITRE ATT&CK Mapping

The `ChatSecOps_MITRE.py` module maps suspicious findings to relevant MITRE ATT&CK techniques.

Examples of mapped techniques may include:

* **T1566.002 – Spearphishing Link**
* **T1071.001 – Application Layer Protocol: Web Protocols**
* **T1583.001 – Acquire Infrastructure: Domains**

The mapping is used to improve the interpretability of the investigation results and provide a security operations context.

---

# 13. Explainable AI (XAI)

The project includes explainability support through `xai_explainer.py`.

This module generates **SHAP-based explanations** to show which lexical / structural features contributed most to the machine learning model’s risk prediction.

Generated outputs may include:

* SHAP waterfall plots
* feature contribution summaries
* explainability figures used in the thesis and reports

Generated figures are typically saved under output directories such as:

* `static/`
* `Report_Figures/`
* `model_outputs/`

depending on the module configuration.

---

# 14. PDF Reporting

The project supports automated report generation for investigated domains / URLs.

An example report is included in the repository as:

```text id="w9v4ra"
Final_Report.pdf
```

Generated reports may contain:

* investigated target information,
* final verdict and risk score,
* threat intelligence findings,
* AI-generated investigation summary,
* MITRE ATT&CK mappings,
* explainability outputs,
* historical memory information.

---

# 15. Natural Language Querying

The project supports querying the stored threat memory database using natural language through `ChatSecOps_NLQuery.py`.

Example queries include:

```text id="z7i5qv"
query Top 5 riskiest domains?
query How many malicious domains in the last 7 days?
query Which countries are threats coming from?
query Which TLDs are most malicious?
```

This functionality is designed to help analysts quickly summarize historical threat data without manually inspecting database entries.

---

# 16. Reproducing the Thesis Demonstration Workflow

A typical end-to-end reproduction workflow is as follows:

## Step 1 — Install dependencies

```bash id="oqv5o5"
pip install -r requirements.txt
```

## Step 2 — Configure the `.env` file

Add all required API keys and Slack credentials.

## Step 3 — Ensure database and output folders are available

The project uses:

* `chatsecops_memory.db`
* `model_outputs/`
* `Report_Figures/`
* `static/`

## Step 4 — Start the main application

```bash id="75vdh0"
python main.py
```

## Step 5 — Run analysis on sample domains / URLs

Example:

```text id="27lv3x"
analyze github.com
analyze fund-fx.co
```

## Step 6 — Observe generated outputs

Depending on the target and configuration, the system may produce:

* Slack investigation summaries
* risk scores
* threat intelligence evidence
* MITRE ATT&CK mappings
* pivot analysis alerts
* XAI/SHAP figures
* PDF reports

---

# 17. Additional Files

## `data_model.ipynb`

This notebook contains model-related development and experimentation work used during the project.

## `checkmodels.py`

Utility script for checking model-related outputs or validating model files.

## `test_api.py`

Used to test API connections and verify that external services are accessible.

## `debug_ogx.py`

Debugging / development utility script.

## `chatsecops_tum_kodlar.txt`

A consolidated text file containing the project code or backup code content.

---

# 18. Notes on Reproducibility

To reproduce the project successfully, ensure that:

1. Python dependencies are installed from `requirements.txt`
2. The `.env` file contains valid API keys
3. Slack credentials are correctly configured if Slack-based execution is required
4. The database file `chatsecops_memory.db` is present or can be created
5. The output directories (`model_outputs`, `Report_Figures`, `static`) are writable
6. Internet access is available for external threat intelligence queries

If some external services are unavailable, some investigation components may be skipped, but the local project structure and rule-based analysis modules can still be inspected and tested.

---

# 19. Authors

**Seray Üstün**
**Şevval Aydoğan**

**Department of Computer Engineering**
**Uskudar University**

---

# 20. Thesis Context

This repository accompanies the undergraduate thesis project on **AI-assisted cyber threat investigation and malicious domain / URL analysis**.
It contains the implementation used for the experimental workflow, case studies, explainability outputs, Slack investigation interface, and reporting pipeline presented in the thesis.
