# 🛡️ DASEC - AI-Powered Phishing Detection and SOC Assistance Platform

<p align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)
![Transformers](https://img.shields.io/badge/HuggingFace-Transformers-yellow)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Phishing-red)
![License](https://img.shields.io/badge/License-MIT-success)

**An AI-powered phishing detection platform combining Machine Learning, Threat Intelligence, Retrieval-Augmented Generation (RAG), OCR and Explainable AI to assist Security Operations Centers (SOCs) in investigating phishing attacks.**

</p>

---

# 📖 Overview

Phishing continues to be one of the primary initial access vectors used by cybercriminals.

Modern phishing campaigns no longer rely solely on fake websites or poorly written emails. Attackers now exploit artificial intelligence, realistic impersonation, malicious PDF attachments, shortened URLs, and sophisticated social engineering techniques.

For Security Operations Centers (SOCs), investigating a single suspicious email often requires consulting multiple security platforms before reaching a conclusion.

**DASEC** was designed to automate and centralize this investigation process.

Instead of relying on a single phishing classifier, DASEC combines multiple Artificial Intelligence models, Threat Intelligence services, document analysis techniques, and contextual reasoning into one unified platform capable of assisting SOC analysts during phishing investigations.

The objective is **not to replace security analysts**, but to accelerate investigations, enrich alerts with contextual intelligence, and provide explainable recommendations that support decision-making.

---

# 🚀 Main Features

## 📧 Comprehensive Email Analysis

DASEC performs a complete investigation of suspicious **.eml** emails.

The platform automatically analyzes:

- Email body
- Subject
- Sender information
- Return-Path
- Reply-To
- Message-ID
- MIME structure
- Attachments
- Embedded URLs
- Email headers

It also validates email authentication mechanisms including:

- SPF
- DKIM
- DMARC

These checks help identify spoofing attempts and sender impersonation.

---

## 🤖 Multi-Model AI Detection

Unlike traditional phishing detectors relying on a single classifier, DASEC combines multiple AI models.

### DistilBERT

A Transformer-based language model capable of understanding semantic relationships inside phishing emails.

Ideal for detecting:

- AI-generated phishing
- Social engineering
- Contextual manipulation
- Spear phishing

---

### TF-IDF + Logistic Regression

A lightweight statistical NLP model providing:

- Fast inference
- Low computational cost
- Strong baseline performance
- Complementary predictions

Using two independent models improves robustness and allows analysts to compare predictions.

---

# 🌐 Advanced URL Analysis

Every extracted URL undergoes multiple security checks.

Analysis includes:

- Lexical analysis
- Suspicious keyword detection
- Brand impersonation detection
- Homoglyph detection
- Suspicious TLD detection
- URL entropy analysis
- WHOIS information
- VirusTotal reputation
- OpenPhish verification

These techniques help detect:

- Typosquatting
- Fake login portals
- Recently registered domains
- Malicious phishing infrastructure

---

# 📎 Attachment Analysis

Attachments frequently contain malicious payloads or phishing lures.

DASEC automatically:

- Computes file hashes
- Checks file reputation using VirusTotal
- Detects suspicious documents
- Extracts embedded text
- Performs OCR on scanned PDFs
- Extracts URLs and Indicators of Compromise (IOCs)

---

# 🖼️ Multimodal Analysis

DASEC combines multiple analysis modalities within a unified pipeline.

Supported modalities include:

- Email text
- PDF documents
- Images extracted through OCR
- URLs
- Metadata
- Email headers

This enables the platform to detect phishing attempts even when malicious content is embedded inside images or scanned documents.

---

# 🔍 Threat Intelligence Integration

DASEC enriches investigations using external Threat Intelligence services.

Current integrations include:

- VirusTotal
- AbuseIPDB
- OpenPhish
- WHOIS

Threat Intelligence enrichment provides valuable context such as:

- Domain reputation
- IP reputation
- Malicious file detection
- Known phishing URLs

---

# 🧠 Retrieval-Augmented Generation (RAG)

Beyond traditional Machine Learning, DASEC integrates a Retrieval-Augmented Generation pipeline.

The RAG engine retrieves cybersecurity knowledge related to the analyzed email before generating explanations.

Examples include:

- Similar phishing campaigns
- Related Indicators of Compromise
- MITRE ATT&CK techniques
- Threat actor profiles
- Historical attack patterns
- Security best practices

This significantly improves contextual explanations while reducing hallucinations from Large Language Models.

---

# 💬 Explainable AI

Instead of returning a simple prediction such as:

```
Phishing detected
Confidence: 98%
```

DASEC generates detailed explanations describing:

- Why the email is suspicious
- Which indicators contributed to the prediction
- Observed attack techniques
- Associated MITRE ATT&CK tactics
- Recommended response actions

The objective is to assist analysts rather than producing opaque AI decisions.

---

# ⚠ IOC Extraction

The platform automatically extracts and correlates Indicators of Compromise including:

- URLs
- Domains
- IP addresses
- Email addresses
- File hashes

These indicators are enriched using Threat Intelligence services and contextualized through the RAG knowledge base.

---

# 📊 SOC Risk Scoring

DASEC combines information collected from:

- Machine Learning models
- Email authentication
- Threat Intelligence
- URL analysis
- IOC extraction
- Attachment analysis
- OCR
- RAG findings

to compute a global phishing risk score.

This score helps analysts prioritize investigations.

---

# 📄 Automated Investigation Reports

DASEC automatically generates detailed PDF reports including:

- Executive summary
- AI prediction
- Confidence scores
- Header analysis
- URL analysis
- Threat Intelligence findings
- IOC summary
- MITRE ATT&CK mapping
- LLM explanation
- Risk assessment
- Analyst recommendations

These reports facilitate documentation and incident response.

---

# 🚨 SIEM Integration

DASEC is designed to integrate into Security Operations Center workflows.

Following analysis, alerts can be forwarded to a SIEM platform where analysts receive:

- Investigation summary
- Risk score
- Threat Intelligence enrichment
- IOC list
- Recommended actions

This enables faster triage and supports incident response processes.

---

# 🏗 System Architecture

```
             Suspicious Email (.eml)
                      │
        ┌─────────────┴─────────────┐
        │                           │
   Header Analysis             Content Analysis
        │                           │
        │                  DistilBERT + TF-IDF
        │                           │
        ├──────────────┐            │
        │              │            │
     URLs         Attachments       │
        │              │            │
 VirusTotal      OCR + Hash         │
 OpenPhish      VirusTotal          │
 WHOIS          IOC Extraction      │
 AbuseIPDB            │             │
        └─────────────┴─────────────┘
                      │
               Threat Intelligence
                      │
                 RAG Knowledge Base
                      │
             MITRE ATT&CK Mapping
                      │
             Explainable AI (LLM)
                      │
             SOC Risk Assessment
                      │
         PDF Report + SIEM Notification
```

---

# 🛠 Technology Stack

- Python
- FastAPI
- Docker
- Hugging Face Transformers
- DistilBERT
- Scikit-learn
- TF-IDF
- Logistic Regression
- ChromaDB
- Sentence Transformers
- SQLite
- Tesseract OCR
- VirusTotal API
- AbuseIPDB API
- OpenPhish
- WHOIS
- Google Gemini
- Groq
- Uvicorn

---

# ⚙ Installation

Clone the repository

```bash
git clone https://github.com/ChanezNouioua-gif/phishing_dasec.git
```

Move into the project

```bash
cd phishing_dasec
```

Create the environment file

```bash
cp .env.example .env
```

Configure your API keys.

Build the Docker container

```bash
docker-compose up --build
```

---

# 🔑 Environment Variables

```
GEMINI_API_KEY=
GROQ_API_KEY=
VT_API_KEY=
ABUSEIPDB_KEY=
SLACK_TOKEN=
```

---

# 📌 Intended Users

DASEC is intended for:

- Security Operations Centers (SOC)
- Blue Teams
- Incident Response Teams
- Cybersecurity Researchers
- Security Students
- Threat Intelligence Analysts

---

# 🎯 Future Improvements

- Multi-language phishing detection
- Sandbox integration
- MISP integration
- Interactive SOC dashboard
- Real-time monitoring
- Additional Threat Intelligence providers

---

# 👩‍💻 Author

**Chanez Nouioua**

Computer Science Engineering Student

Artificial Intelligence Specialization

---

⭐ If you find this project interesting, consider giving it a star.
