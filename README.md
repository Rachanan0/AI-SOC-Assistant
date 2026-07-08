# 🛡️ AI SOC Assistant – Intelligent Security Operations Platform

![Project Banner](screenshots/banner.png)

## 🚀 Project Overview

**AI SOC Assistant** is an AI-powered Security Operations Center (SOC) investigation platform designed to help security analysts monitor, investigate, and respond to cybersecurity threats faster.

The platform integrates **Splunk Enterprise SIEM** with **Python automation, LLM-based analysis, and security intelligence capabilities** to automate common SOC tasks such as:

- Security event monitoring
- Threat hunting
- SPL query generation
- Windows event log analysis
- MITRE ATT&CK technique mapping
- IOC extraction
- Threat intelligence enrichment
- Automated incident report generation


The objective of this project is to simulate a real-world SOC environment where an analyst can investigate security alerts using an AI-powered assistant.

---

# 🏗️ Architecture
                Windows Endpoint
                       |
                       |
              Windows Security Logs
                       |
                       |
          Splunk Universal Forwarder
                       |
                       |
                       ▼

             +----------------+
             | Splunk SIEM    |
             | Enterprise     |
             +----------------+

                       |
                       |
                 REST API (8089)

                       |
                       ▼

          +-----------------------+
          | Python Security Engine|
          +-----------------------+

          | Query Generator       |
          | AI Analyst Engine     |
          | IOC Extractor         |
          | MITRE Mapper          |
          | Report Generator      |

                       |
                       ▼

             Streamlit Dashboard

                       |
                       ▼

                  SOC Analyst


---

# 🎯 Problem Statement

Security analysts spend significant time manually:

- Searching through thousands of logs
- Writing SIEM queries
- Investigating suspicious activities
- Mapping attacks to MITRE ATT&CK
- Creating incident reports


AI SOC Assistant reduces investigation time by providing an intelligent interface where analysts can ask security questions in natural language.

Example:

The AI assistant automatically generates:

```spl
index=main EventCode=4625 earliest=-24h

Analyst Query
Show failed login attempts today.

AI Generated SPL
index=main EventCode=4625 earliest=-24h
AI Investigation
Detected multiple failed authentication attempts.

Possible brute force activity.

Severity:
High

Recommendation:
Investigate source IP,
review affected accounts,
and apply account protection measures.

Automated Threat Hunting
The system generates SPL queries for common attack scenarios.

Supported hunts:

Brute Force Attack

Windows Event:

4625

MITRE:

T1110 - Brute Force
PowerShell Abuse

Windows Event:

4688

MITRE:

T1059 - Command and Scripting Interpreter
Suspicious Service Installation

Windows Event:

7045

MITRE:

T1543.003 - Windows Service

MITRE ATT&CK Mapping Engine:

Windows Event 4625

        ↓

Multiple Failed Authentication Attempts

        ↓

Brute Force

        ↓

MITRE T1110

IOC Extraction Engine:

Automatically extracts Indicators of Compromise from logs.

Detects:

IPv4 addresses
Domains
URLs
Email addresses
MD5 hashes
SHA256 hashes

Example:
Suspicious connection detected:

IP:
185.xxx.xxx.xxx


Hash:
a3f89cxxxxxxxx

Threat Intelligence Integration

Enriches detected indicators using external intelligence sources.

Integrations:

Platform	Purpose

VirusTotal	         Malware and hash reputation
AbuseIPDB	           IP reputation checking
AlienVault OTX	     Threat intelligence
Shodan	             Internet exposure information

Automated Incident Report Generation

Generates professional SOC investigation reports.
Incident Summary

Alert Details

Timeline

Evidence

Affected Hosts

User Accounts

Indicators of Compromise

MITRE ATT&CK Techniques

Containment Actions

Recommendations

Output:

incident_report.pdf

📊 Dashboard Analytics

The dashboard provides:

Failed authentication trends
Event distribution
Top users
Top hosts
Alert severity
Investigation timeline

🛠️ Technology Stack
Component	Technology
SIEM Platform	Splunk Enterprise
Log Collection	Splunk Universal Forwarder
Backend	Python
Frontend	Streamlit
Data Processing	Pandas
Visualization	Plotly
AI Engine	OpenAI API / Ollama
Reporting	ReportLab
Threat Intelligence	VirusTotal, AbuseIPDB
Framework	MITRE ATT&CK
Version Control	GitHub


📂 Repository Structure
AI-SOC-Assistant/

│
├── app.py                     # Streamlit application
├── config.py                  # Configuration management
├── splunk_client.py           # Splunk API integration
├── ai_engine.py               # AI analysis engine
├── query_generator.py         # Natural language → SPL
├── report_generator.py        # PDF report generation
├── utils.py                   # Utility functions
│
├── pages/
│   ├── Dashboard.py
│   ├── Investigation.py
│   ├── Threat_Hunting.py
│   ├── Reports.py
│
├── prompts/
│
├── reports/
│
├── screenshots/
│
├── architecture/
│
├── docs/
│
└── tests/
⚙️ Installation
Clone Repository
git clone https://github.com/Rachanan0/AI-SOC-Assistant.git

Move into project:

cd AI-SOC-Assistant

Install dependencies:

pip install -r requirements.txt

Configure environment:

.env.example → .env
🔐 Environment Variables

Example:

SPLUNK_HOST=
SPLUNK_PORT=
SPLUNK_USERNAME=
SPLUNK_PASSWORD=

OPENAI_API_KEY=

VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
▶️ Running Application

Start Streamlit:

streamlit run app.py

Application opens:

http://localhost:8501
📸 Screenshots
SOC Dashboard
screenshots/Dashboard.png
AI Investigation
screenshots/AI_Assistant.png
Threat Hunting
screenshots/Threat_Hunting.png
Incident Report
screenshots/Incident_Report.png
🧪 Testing

Run tests:

pytest tests/
🔮 Future Enhancements

Planned improvements:

Automated alert prioritization
SOAR integration
Machine learning anomaly detection
Real-time detection rules
Multiple SIEM support
Automated containment actions
👩‍💻 Author

Rachana

Cybersecurity Student | SOC Analyst Aspirant

Skills:

SIEM Monitoring
Threat Hunting
Incident Response
Security Automation
Python Development
⭐ Project Impact

This project demonstrates practical experience in:

✅ SOC Operations
✅ Splunk SIEM
✅ Windows Event Analysis
✅ Threat Hunting
✅ MITRE ATT&CK Framework
✅ Incident Response
✅ Security Automation
✅ AI for Cybersecurity


This README is closer to what a **SOC Analyst L1 recruiter or cybersecurity engineer** expects to see. It positions the project as a **security operations platform**, not just an AI application.
