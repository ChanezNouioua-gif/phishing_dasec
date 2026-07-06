import re, os, sys, json, pickle, hashlib, time, uuid, yaml, sqlite3, threading
import torch
import numpy as np
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.parser import BytesParser
from io import BytesIO
from typing import Optional
from datetime import datetime, timezone

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from email.header import decode_header as _dh

from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from sentence_transformers import SentenceTransformer
import chromadb
import pytesseract
from PIL import Image
import Levenshtein
import whois


from reportlab.lib.pagesizes import letter
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from orchestrator_agent import OrchestratorAgent



# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════
BASE_DIR        = os.getenv("BASE_DIR", "/app")
VECTORSTORE_DIR = os.getenv("VECTORSTORE_DIR", "/app/data/vectorstore")
IOC_CACHE_DIR   = os.getenv("IOC_CACHE_DIR", "/app/data/ioc_cache")
DB_PATH         = os.getenv("DB_PATH", "/app/data/dasec.db")
PDF_OUTPUT_DIR  = os.getenv("PDF_OUTPUT_DIR", "/tmp/dasec_reports")



os.makedirs(PDF_OUTPUT_DIR, exist_ok=True)
os.makedirs(VECTORSTORE_DIR, exist_ok=True)
os.makedirs(IOC_CACHE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

SLACK_TOKEN     = os.getenv("SLACK_TOKEN", "")
SLACK_CHANNEL   = "#soc-alerts"

# Seuils de verdict — remontés suite à observation empirique : beaucoup d'emails
# légitimes (headers SPF/DKIM absents en test, RAG qui remonte toujours une technique
# MITRE "la plus proche" même hors sujet) atterrissaient entre 0.14 et 0.52 et étaient
# classés SUSPECT. Ajustables via variables d'env sans redéploiement de code.
SCORE_THRESHOLD_SUSPECT  = float(os.getenv("SCORE_THRESHOLD_SUSPECT", "0.40"))
SCORE_THRESHOLD_PHISHING = float(os.getenv("SCORE_THRESHOLD_PHISHING", "0.70"))
SOC_THRESHOLD   = SCORE_THRESHOLD_PHISHING

KNOWN_BRANDS = [
    "paypal","microsoft","google","apple","amazon","netflix",
    "facebook","instagram","twitter","linkedin","dhl","fedex",
    "bnpparibas","societegenerale","creditagricole","orange","sfr",
    "docusign","dropbox","wellsfargo","chase","bankofamerica",
]
SUSPICIOUS_TLDS = {
    ".tk",".xyz",".click",".top",".link",".info",
    ".biz",".ru",".cn",".pw",".ga",".ml",".cf",".gq",
}

# ══════════════════════════════════════════════════════════════
# SQLITE
# ══════════════════════════════════════════════════════════════
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id     TEXT    UNIQUE NOT NULL,
            analyzed_at     TEXT    NOT NULL,
            mode            TEXT    NOT NULL,
            score_global    REAL    NOT NULL,
            verdict         TEXT    NOT NULL,
            confidence      TEXT,
            sender          TEXT,
            subject         TEXT,
            technique_attck TEXT,
            campaign        TEXT,
            vecteur_attaque TEXT,
            sigma_count     INTEGER DEFAULT 0,
            alert_sent      INTEGER DEFAULT 0,
            report_json     TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS iocs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL,
            ioc_type    TEXT NOT NULL,
            ioc_value   TEXT NOT NULL,
            source      TEXT,
            detected_at TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id)
        );
        CREATE INDEX IF NOT EXISTS idx_analyses_verdict ON analyses(verdict);
        CREATE INDEX IF NOT EXISTS idx_analyses_score   ON analyses(score_global);
        CREATE INDEX IF NOT EXISTS idx_analyses_date    ON analyses(analyzed_at);
        CREATE INDEX IF NOT EXISTS idx_iocs_analysis_id ON iocs(analysis_id);
        CREATE INDEX IF NOT EXISTS idx_iocs_type        ON iocs(ioc_type);
    """)
    con.commit()
    con.close()

init_db()

def save_analysis(result: dict, mode: str = "text", sender: str = "",
                  subject: str = "", alert_sent: bool = False) -> str:
    analysis_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    report  = result.get("report", {})
    sigma_r = result.get("sigma_rules", {})
    iocs    = report.get("iocs", {})
    ti      = result.get("threat_intel", result.get("modules", {}).get("threat_intel", {}))

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        INSERT OR IGNORE INTO analyses
          (analysis_id, analyzed_at, mode, score_global, verdict, confidence,
           sender, subject, technique_attck, campaign, vecteur_attaque,
           sigma_count, alert_sent, report_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        analysis_id, now, mode, result.get("score_global", 0.0),
        report.get("verdict", result.get("verdict", "UNKNOWN")),
        report.get("confiance", ""), sender, subject,
        report.get("technique_attck", ""), report.get("campagne_probable", ""),
        report.get("vecteur_attaque", ""), sigma_r.get("rules_count", 0),
        int(alert_sent), json.dumps(result, ensure_ascii=False),
    ))

    rows = []
    for url in iocs.get("urls_suspectes", []):
        rows.append((analysis_id, "url", url, "pipeline", now))
    for ip in iocs.get("ips_malveillantes", []):
        rows.append((analysis_id, "ip", ip, "AbuseIPDB", now))
    for h in iocs.get("hashes", []):
        rows.append((analysis_id, "hash", h, "VirusTotal", now))
    for ioc_str in ti.get("iocs_detected", []):
        src = "VT" if "VT" in ioc_str else ("AbuseIPDB" if "AbuseIPDB" in ioc_str else "TI")
        rows.append((analysis_id, "ioc_external", ioc_str[:200], src, now))
    if rows:
        cur.executemany(
            "INSERT INTO iocs (analysis_id, ioc_type, ioc_value, source, detected_at) VALUES (?,?,?,?,?)",
            rows
        )
    con.commit()
    con.close()
    return analysis_id

def get_recent_analyses(limit: int = 20, verdict_filter: str = None) -> list:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    if verdict_filter:
        cur.execute("""SELECT analysis_id, analyzed_at, mode, score_global, verdict,
                       sender, subject, technique_attck, campaign, sigma_count, alert_sent
                       FROM analyses WHERE verdict = ? ORDER BY analyzed_at DESC LIMIT ?""",
                   (verdict_filter.upper(), limit))
    else:
        cur.execute("""SELECT analysis_id, analyzed_at, mode, score_global, verdict,
                       sender, subject, technique_attck, campaign, sigma_count, alert_sent
                       FROM analyses ORDER BY analyzed_at DESC LIMIT ?""", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows

def get_analysis_by_id(analysis_id: str):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,))
    row = cur.fetchone()
    con.close()
    if not row:
        return None
    d = dict(row)
    try:
        d["report_full"] = json.loads(d.pop("report_json"))
    except Exception:
        d["report_full"] = {}
    return d

def get_iocs_by_analysis(analysis_id: str) -> list:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("""SELECT ioc_type, ioc_value, source, detected_at FROM iocs
                   WHERE analysis_id = ? ORDER BY ioc_type""", (analysis_id,))
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows

def get_stats() -> dict:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM analyses")
    total = cur.fetchone()[0]
    cur.execute("SELECT verdict, COUNT(*) FROM analyses GROUP BY verdict")
    by_verdict = dict(cur.fetchall())
    cur.execute("SELECT AVG(score_global) FROM analyses")
    avg_score = round(cur.fetchone()[0] or 0.0, 4)
    cur.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cur.fetchone()[0]
    cur.execute("""SELECT technique_attck, COUNT(*) c FROM analyses
                   WHERE technique_attck != '' GROUP BY technique_attck
                   ORDER BY c DESC LIMIT 5""")
    top_techniques = cur.fetchall()
    cur.execute("""SELECT campaign, COUNT(*) c FROM analyses
                   WHERE campaign != '' GROUP BY campaign
                   ORDER BY c DESC LIMIT 5""")
    top_campaigns = cur.fetchall()
    con.close()
    return {
        "total_analyses": total, "by_verdict": by_verdict, "avg_score": avg_score,
        "total_iocs": total_iocs,
        "top_techniques": [{"technique": t, "count": c} for t, c in top_techniques],
        "top_campaigns": [{"campaign": c, "count": n} for c, n in top_campaigns],
    }

# ══════════════════════════════════════════════════════════════
# PDF — ReportLab natif (fix indentation Sigma)
# ══════════════════════════════════════════════════════════════
_VERDICT_COLORS = {
    "PHISHING": colors.HexColor("#A32D2D"),
    "SUSPECT":  colors.HexColor("#854F0B"),
    "LEGITIME": colors.HexColor("#3B6D11"),
    "ERREUR":   colors.HexColor("#5F5E5A"),
}

def _pdf_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="DasecTitle", parent=styles["Title"],
        fontSize=22, textColor=colors.HexColor("#042C53"), spaceAfter=4, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="DasecSubtitle", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#5F5E5A"), spaceAfter=18))
    styles.add(ParagraphStyle(name="SectionHeading", parent=styles["Heading2"],
        fontSize=13, textColor=colors.HexColor("#042C53"), spaceBefore=18, spaceAfter=8))
    styles.add(ParagraphStyle(name="BodyDasec", parent=styles["Normal"],
        fontSize=10, leading=15, textColor=colors.HexColor("#2C2C2A")))
    styles.add(ParagraphStyle(name="Mono", parent=styles["Normal"],
        fontName="Courier", fontSize=8.5, leading=11,
        textColor=colors.HexColor("#2C2C2A"), backColor=colors.HexColor("#F1EFE8"),
        spaceAfter=0))
    styles.add(ParagraphStyle(name="VerdictBig", parent=styles["Normal"],
        fontSize=20, leading=24, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="ScoreLabel", parent=styles["Normal"],
        fontSize=9, alignment=TA_CENTER, textColor=colors.HexColor("#5F5E5A")))
    return styles

_STYLES = _pdf_styles()

def _score_bar(score, verdict):
    width_total = 14 * cm
    filled = max(0.02, min(score, 1.0)) * width_total
    empty  = width_total - filled
    color  = _VERDICT_COLORS.get(verdict, colors.grey)
    t = Table([["", ""]], colWidths=[filled, empty], rowHeights=[0.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), color),
        ("BACKGROUND", (1,0), (1,0), colors.HexColor("#D3D1C7")),
    ]))
    return t

def _findings_table(rows, headers, col_widths=None):
    if not rows:
        return Paragraph("<i>Aucune donnée</i>", _STYLES["BodyDasec"])
    data = [headers] + rows
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#042C53")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 8.5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F1EFE8")]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#D3D1C7")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6), ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 5), ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    return t

def generate_pdf_report(result: dict, output_path: str = None) -> str:
    if output_path is None:
        aid = result.get("analysis_id", "unknown")[:8]
        output_path = f"{PDF_OUTPUT_DIR}/DASEC_report_{aid}.pdf"

    report       = result.get("report", {})
    sigma_r      = result.get("sigma_rules", {})
    score_global = result.get("score_global", 0.0)
    email_meta   = result.get("email_meta", {})
    modules      = result.get("modules", {})
    nlp          = modules.get("nlp", result.get("nlp", {}))
    urls_mod     = modules.get("urls", result.get("urls", {}))
    headers_mod  = modules.get("headers", {})
    attach_mod   = modules.get("attachments", {})
    rag          = modules.get("rag", result.get("rag", {}))
    ti           = modules.get("threat_intel", result.get("threat_intel", {}))

    doc = SimpleDocTemplate(output_path, pagesize=letter,
        topMargin=2*cm, bottomMargin=2*cm, leftMargin=2*cm, rightMargin=2*cm,
        title="DASEC — Rapport d'analyse phishing")
    story = []

    story.append(Paragraph("DASEC", _STYLES["DasecTitle"]))
    story.append(Paragraph(
        f"Rapport d'analyse automatisée de phishing — généré le "
        f"{datetime.now().strftime('%d/%m/%Y à %H:%M')}", _STYLES["DasecSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#D3D1C7")))
    story.append(Spacer(1, 12))

    verdict = report.get("verdict", "INCONNU")
    color = _VERDICT_COLORS.get(verdict, colors.grey)
    verdict_style = ParagraphStyle(name="VerdictColored", parent=_STYLES["VerdictBig"], textColor=color)
    story.append(Paragraph(f"<b>{verdict}</b>", verdict_style))
    story.append(Spacer(1, 6))
    story.append(_score_bar(score_global, verdict))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Score global : <b>{score_global:.2f}</b> / 1.00 &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"Confiance : <b>{report.get('confiance','N/A')}</b>", _STYLES["ScoreLabel"]))
    story.append(Spacer(1, 16))

    story.append(Paragraph("Métadonnées de l'email", _STYLES["SectionHeading"]))
    meta_rows = [
        ["Expéditeur", email_meta.get("from", "N/A")],
        ["Sujet",      email_meta.get("subject", "N/A")],
        ["Date",       email_meta.get("date", "N/A")],
        ["Vecteur d'attaque", report.get("vecteur_attaque", "N/A")],
    ]
    t = Table(meta_rows, colWidths=[4*cm, 12*cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 9.5),
        ("VALIGN", (0,0), (-1,-1), "TOP"), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Analyse", _STYLES["SectionHeading"]))
    story.append(Paragraph(report.get("explication", "N/A"), _STYLES["BodyDasec"]))
    story.append(Spacer(1, 8))
    reco_style = ParagraphStyle(name="Reco", parent=_STYLES["BodyDasec"],
        backColor=colors.HexColor("#FAEEDA"), borderPadding=8)
    story.append(Paragraph(f"<b>Recommandation :</b> {report.get('recommandation','N/A')}", reco_style))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Threat Intelligence", _STYLES["SectionHeading"]))
    ti_rows = [
        ["Technique MITRE ATT&CK", report.get("technique_attck", "N/A")],
        ["Campagne probable",      report.get("campagne_probable", "N/A")],
    ]
    if rag.get("apt_groups"):
        top_apt = rag["apt_groups"][0]
        ti_rows.append(["Groupe APT le plus proche",
                        f"{top_apt.get('name','')} ({top_apt.get('group_id','')})"])
    t = Table(ti_rows, colWidths=[5*cm, 11*cm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 9.5),
        ("VALIGN", (0,0), (-1,-1), "TOP"), ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    if ti.get("iocs_detected"):
        story.append(Paragraph("IoCs confirmés (VirusTotal / AbuseIPDB) :", _STYLES["BodyDasec"]))
        for ioc in ti["iocs_detected"][:10]:
            story.append(Paragraph(f"&bull; {ioc}", _STYLES["BodyDasec"]))
        story.append(Spacer(1, 8))

    story.append(Paragraph("Indicateurs détectés", _STYLES["SectionHeading"]))
    indicateurs = report.get("indicateurs_cles", [])
    if indicateurs:
        rows = [[f"{i+1}", ind] for i, ind in enumerate(indicateurs)]
        story.append(_findings_table(rows, ["#", "Indicateur"], [1.2*cm, 14.8*cm]))
    else:
        story.append(Paragraph("Aucun indicateur spécifique détecté.", _STYLES["BodyDasec"]))
    story.append(Spacer(1, 12))

    iocs = report.get("iocs", {})
    if any(iocs.get(k) for k in ("urls_suspectes","ips_malveillantes","hashes")):
        story.append(Paragraph("Indicateurs de compromission (IoCs)", _STYLES["SectionHeading"]))
        ioc_rows = []
        for url in iocs.get("urls_suspectes", []): ioc_rows.append(["URL", url])
        for ip in iocs.get("ips_malveillantes", []): ioc_rows.append(["IP", ip])
        for h in iocs.get("hashes", []): ioc_rows.append(["Hash SHA256", h])
        story.append(_findings_table(ioc_rows, ["Type", "Valeur"], [3*cm, 13*cm]))
        story.append(Spacer(1, 12))

    story.append(Paragraph("Détail des scores par module", _STYLES["SectionHeading"]))
    score_rows = [
        ["NLP (DistilBERT + TF-IDF)", f"{nlp.get('score', 0):.3f}"],
        ["URLs",                      f"{urls_mod.get('score', 0):.3f}"],
        ["Threat Intelligence",       f"{ti.get('score', 0):.3f}"],
    ]
    if headers_mod:
        score_rows.insert(0, ["Headers SMTP (SPF/DKIM/DMARC)", f"{headers_mod.get('score', 0):.3f}"])
    if attach_mod:
        score_rows.append(["Pièces jointes", f"{attach_mod.get('score', 0):.3f}"])
    story.append(_findings_table(score_rows, ["Module", "Score (0-1)"], [11*cm, 5*cm]))
    story.append(Spacer(1, 14))

    if sigma_r.get("rules_count", 0) > 0:
        story.append(PageBreak())
        story.append(Paragraph("Règles Sigma générées", _STYLES["SectionHeading"]))
        story.append(Paragraph(
            f"{sigma_r['rules_count']} règle(s) prête(s) à déployer dans un SIEM "
            f"(Splunk, Elastic, Microsoft Sentinel, QRadar).", _STYLES["BodyDasec"]))
        story.append(Spacer(1, 8))
        combined_yaml = sigma_r.get("combined_yaml", "")
        for line in combined_yaml.split("\n"):
            safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            stripped = safe_line.lstrip(" ")
            leading_spaces = len(safe_line) - len(stripped)
            if leading_spaces > 0:
                safe_line = ("&nbsp;" * leading_spaces) + stripped
            story.append(Paragraph(safe_line if safe_line.strip() else "&nbsp;", _STYLES["Mono"]))
        story.append(Spacer(1, 12))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#D3D1C7")))
    disclaimer_style = ParagraphStyle(name="Disclaimer", parent=_STYLES["Normal"],
        fontSize=8, textColor=colors.HexColor("#888780"))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Rapport généré automatiquement par DASEC (Detection Automatisée et "
        "Sécurisée des E-mails Compromis). Ce rapport est destiné à assister "
        "l'analyste SOC dans sa prise de décision et ne remplace pas une "
        "investigation manuelle pour les cas à fort enjeu.", disclaimer_style))

    doc.build(story)
    return output_path

# ══════════════════════════════════════════════════════════════
# CHARGEMENT MODÈLES
# ══════════════════════════════════════════════════════════════
print("⏳ Chargement des modèles...")

with open(os.getenv("TFIDF_PATH", "/app/models/tfidf_lr_pipeline.pkl"), "rb") as f:
    artifacts = pickle.load(f)
tfidf    = artifacts["tfidf"]
lr_model = artifacts["lr_model"]

BERT_PATH  = os.getenv("BERT_PATH", "/app/models/distilbert-5000/final")
tokenizer  = DistilBertTokenizerFast.from_pretrained(BERT_PATH)
bert_model = DistilBertForSequenceClassification.from_pretrained(BERT_PATH)
bert_model.eval()

embedder      = SentenceTransformer("all-MiniLM-L6-v2")
chroma_client = chromadb.PersistentClient(path=VECTORSTORE_DIR)

def embed_fn(texts):
    return embedder.encode(texts).tolist()

def _get_col(name):
    try:
        return chroma_client.get_collection(name)
    except Exception:
        return None

col_techniques = _get_col("mitre_techniques")
col_apt        = _get_col("mitre_apt_groups")
col_ti         = _get_col("threat_intel")
col_live       = _get_col("live_ioc_feeds")
RAG_OK         = all([col_techniques, col_apt, col_ti])

import json as _json
def _load_set_txt(path):
    """Charge un fichier texte (une URL/ligne, # = commentaire) en set."""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = {l.strip() for l in f if l.strip() and not l.startswith("#")}
        print(f"✅ Feed chargé : {path} — {len(lines):,} entrées")
        return lines
    except FileNotFoundError:
        print(f"⚠️ Feed introuvable : {path}")
        return set()
    except Exception as e:
        print(f"⚠️ Erreur chargement feed {path} : {e}")
        return set()

urlhaus_set   = _load_set_txt(f"{IOC_CACHE_DIR}/urlhaus.abuse.ch.txt")
openphish_set = _load_set_txt(f"{IOC_CACHE_DIR}/openphish.txt")


llm_client  = None
llm_backend = None
GROQ_KEY   = os.getenv("GROQ_API_KEY", "")
GEMINI_KEY = os.getenv("GEMINI_API_KEY", "")

if GROQ_KEY:
    try:
        from groq import Groq
        llm_client  = Groq(api_key=GROQ_KEY)
        llm_backend = "groq"
        print("✅ LLM : Groq")
    except Exception as e:
        print(f"⚠️ Groq : {e}")

if not llm_client and GEMINI_KEY:
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_KEY)
        llm_client  = genai.GenerativeModel("gemini-2.5-flash")
        llm_backend = "gemini"
        print("✅ LLM : Gemini")
    except Exception as e:
        print(f"⚠️ Gemini : {e}")

if not llm_client:
    print("⚠️ Aucun LLM — mode rapport structuré")

print(f"✅ Chargé | RAG={'OK' if RAG_OK else 'KO'} | LLM={llm_backend or 'none'} "
      f"| URLHaus={len(urlhaus_set):,} | OpenPhish={len(openphish_set):,} | DB={DB_PATH}")

# ══════════════════════════════════════════════════════════════
# THREAT INTEL
# ══════════════════════════════════════════════════════════════
VT_API_KEY    = os.getenv("VT_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
_ti_cache     = {}
_ti_cache_lock = threading.Lock()
_ti_executor  = ThreadPoolExecutor(max_workers=4)
VT_BASE_URL    = "https://www.virustotal.com/api/v3"
ABUSE_BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def _vt_check_hash(sha256, timeout=5):
    cache_key = f"vt_hash:{sha256}"
    with _ti_cache_lock:
        if cache_key in _ti_cache:
              return _ti_cache[cache_key]
    if not VT_API_KEY: return {"checked": False, "malicious": False, "reason": "no_api_key"}
    try:
        import requests as _rq
        r = _rq.get(f"{VT_BASE_URL}/files/{sha256}", headers={"x-apikey": VT_API_KEY}, timeout=timeout)
        if r.status_code == 404:
            result = {"checked": True, "malicious": False, "reason": "not_in_vt", "malicious_count": 0, "total_engines": 0}
        elif r.status_code == 200:
            data  = r.json()["data"]["attributes"]
            stats = data.get("last_analysis_stats", {})
            malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
            result = {"checked": True, "malicious": (malicious+suspicious) > 0,
                      "malicious_count": malicious, "suspicious_count": suspicious,
                      "total_engines": sum(stats.values()) if stats else 0, "names": data.get("names", [])[:3]}
        else:
            result = {"checked": False, "malicious": False, "reason": f"http_{r.status_code}"}
        with _ti_cache_lock:
            _ti_cache[cache_key] = result
        return result
    except Exception as e:
        return {"checked": False, "malicious": False, "reason": str(e)[:80]}

def _vt_check_url(target_url, timeout=5):
    cache_key = f"vt_url:{target_url}"
    with _ti_cache_lock:
        if cache_key in _ti_cache:
            return _ti_cache[cache_key]
    if not VT_API_KEY: return {"checked": False, "malicious": False, "reason": "no_api_key"}
    try:
        import requests as _rq, base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        r = _rq.get(f"{VT_BASE_URL}/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=timeout)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"].get("last_analysis_stats", {})
            malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
            result = {"checked": True, "malicious": (malicious+suspicious) > 0,
                      "malicious_count": malicious, "suspicious_count": suspicious,
                      "total_engines": sum(stats.values()) if stats else 0}
        elif r.status_code == 404:
            result = {"checked": True, "malicious": False, "reason": "not_in_vt"}
        else:
            result = {"checked": False, "malicious": False, "reason": f"http_{r.status_code}"}
        _ti_cache[cache_key] = result
        with _ti_cache_lock:
            _ti_cache[cache_key] = result
        return result
    except Exception as e:
        return {"checked": False, "malicious": False, "reason": str(e)[:80]}

def _abuseipdb_check(ip, timeout=5):
    cache_key = f"abuse:{ip}"
    with _ti_cache_lock:
        if cache_key in _ti_cache:
            return _ti_cache[cache_key]
    if not ABUSEIPDB_KEY: return {"checked": False, "malicious": False, "reason": "no_api_key"}
    try:
        import requests as _rq
        r = _rq.get(ABUSE_BASE_URL, headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=timeout)
        if r.status_code == 200:
            data  = r.json()["data"]
            score = data.get("abuseConfidenceScore", 0)
            result = {"checked": True, "malicious": score >= 50, "abuse_score": score,
                      "total_reports": data.get("totalReports", 0), "country": data.get("countryCode", ""),
                      "isp": data.get("isp", ""), "is_tor": data.get("isTor", False)}
        else:
            result = {"checked": False, "malicious": False, "reason": f"http_{r.status_code}"}
        _ti_cache[cache_key] = result
        with _ti_cache_lock:
            _ti_cache[cache_key] = result
        return result
    except Exception as e:
        return {"checked": False, "malicious": False, "reason": str(e)[:80]}

def threat_intel_check(urls=None, ips=None, hashes=None):
    urls, ips, hashes = urls or [], ips or [], hashes or []
    iocs_detected, details = [], {"urls": [], "ips": [], "hashes": []}
    apis_used = {"virustotal": bool(VT_API_KEY), "abuseipdb": bool(ABUSEIPDB_KEY)}
    score = 0.0

    def _run(fn, arg, timeout=6):
        try: return _ti_executor.submit(fn, arg).result(timeout=timeout)
        except Exception as e: return {"checked": False, "malicious": False, "reason": str(e)[:80]}

    for h in hashes[:2]:
        r = _run(_vt_check_hash, h)
        details["hashes"].append({"hash": h, **r})
        if r.get("malicious"):
            score += 0.95
            iocs_detected.append(f"Hash malveillant (VT {r.get('malicious_count',0)}/{r.get('total_engines',0)}) : {h[:16]}...")

    for u in urls[:3]:
        r = _run(_vt_check_url, u)
        details["urls"].append({"url": u, **r})
        if r.get("malicious"):
            score += 0.85
            iocs_detected.append(f"URL malveillante (VT {r.get('malicious_count',0)}/{r.get('total_engines',0)}) : {u[:50]}")

    for ip in ips[:3]:
        r = _run(_abuseipdb_check, ip)
        details["ips"].append({"ip": ip, **r})
        if r.get("malicious"):
            score += 0.70
            iocs_detected.append(f"IP malveillante (AbuseIPDB {r.get('abuse_score',0)}%) : {ip}")

    return {"score": round(min(score, 1.0), 4), "iocs_detected": iocs_detected, "details": details, "apis_used": apis_used}

# ══════════════════════════════════════════════════════════════
# UTILITAIRES
# ══════════════════════════════════════════════════════════════
def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"\d+", " NUM ", text)
    text = re.sub(r"[^\w\s]", " ", text)
    return re.sub(r"\s+", " ", text).strip()

def extract_urls(text):
    return list(set(re.findall(r"https?://[^\s<>\"\']+|www\.[^\s<>\"\']+", text)))

def get_domain(url):
    """Extrait le domaine d'une URL (http(s)://... ou www...). Ne JAMAIS utiliser sur
    des adresses email ou des chaînes 'Display Name <addr>' — utiliser get_email_domain."""
    m = re.search(r"(?:https?://)?(?:www\.)?([^/\s]+)", url)
    return m.group(1).lower() if m else ""

def get_email_domain(addr):
    """Extrait le domaine d'une adresse email, en ignorant le nom d'affichage
    (ex: '\"NovaTech RH\" <hr-noreply@novatech-solutions.com>' -> 'novatech-solutions.com').
    Seule fonction à utiliser pour comparer des adresses From/Reply-To/Return-Path —
    ne jamais utiliser get_domain() (prévue pour des URLs) sur ces champs : appliquée à une
    chaîne 'Display Name <addr>', get_domain() ne capture que le premier mot du nom
    d'affichage (ex: 'novatech' au lieu de 'novatech-solutions.com'), ce qui génère de
    faux positifs de type 'Return-Path ≠ From' même quand les deux domaines sont identiques."""
    if not addr:
        return ""
    m = re.search(r'@([\w.\-]+)', addr)
    return m.group(1).lower().rstrip(">").strip() if m else ""



def parse_eml(raw_bytes: bytes) -> dict:
    # 1. Gestion robuste du parsing avec fallback si l'e-mail est mal formé
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception:
        msg = BytesParser(policy=policy.compat32).parsebytes(raw_bytes)
    
    # 2. Fonction interne pour décoder proprement les headers (ex: =?utf-8?B?...?=)
    def _decode_header(val):
        if not val:
            return ""
        try:
            parts = _dh(str(val))
            result = []
            for part, enc in parts:
                if isinstance(part, bytes):
                    # Si aucun encodage n'est détecté, on fallback sur utf-8 ou ignore les erreurs
                    result.append(part.decode(enc or "utf-8", errors="replace"))
                else:
                    result.append(str(part))
            return " ".join(result).strip()
        except Exception:
            return str(val).strip() # Sécurité si le décodage échoue complètement

    # 3. Extraction et parcours du contenu du mail
    body_text, body_html = "", ""
    images, attachments = [], []
    
    for part in msg.walk():
        ct = part.get_content_type()
        cd = str(part.get("Content-Disposition", ""))
        
        if ct == "text/plain" and "attachment" not in cd:
            body_text += part.get_content() or ""
        elif ct == "text/html" and "attachment" not in cd:
            body_html += str(part.get_content() or "")
        elif ct.startswith("image/"):
            images.append({
                "content_type": ct, 
                "data": part.get_payload(decode=True), 
                "name": _decode_header(part.get_filename("image"))
            })
        elif "attachment" in cd or part.get_filename():
            payload = part.get_payload(decode=True)
            if payload:
                filename = _decode_header(part.get_filename("unknown"))
                attachments.append({
                    "filename": filename, 
                    "content_type": ct,
                    "data": payload, 
                    "md5": hashlib.md5(payload).hexdigest(),
                    "sha256": hashlib.sha256(payload).hexdigest(), 
                    "size": len(payload)
                })
                
    # 4. Nettoyage du HTML et extraction globale du texte
    body_html_clean = re.sub(r"<[^>]+>", " ", body_html)
    full_text = f"{body_text} {body_html_clean}".strip()
    
    # 5. Construction du dictionnaire de retour avec headers décodés
    return {
        "headers": dict(msg.items()), 
        "from": _decode_header(msg.get("From", "")), 
        "reply_to": _decode_header(msg.get("Reply-To", "")),
        "return_path": _decode_header(msg.get("Return-Path", "")),
        "to": _decode_header(msg.get("To", "")), 
        "subject": _decode_header(msg.get("Subject", "")), 
        "date": _decode_header(msg.get("Date", "")),
        "message_id": _decode_header(msg.get("Message-ID", "")), 
        "x_mailer": _decode_header(msg.get("X-Mailer", "")), 
        "body_text": body_text,
        "body_html": body_html, 
        "full_text": full_text, 
        "images": images, 
        "attachments": attachments,
        "urls_in_html": extract_urls(body_html), 
        "urls_in_text": extract_urls(body_text)
    }

def analyze_headers(parsed):
    headers, findings, score = parsed["headers"], [], 0.0
    auth = str(headers.get("Authentication-Results", "")).lower()
    spf  = str(headers.get("Received-SPF", "")).lower()
    dkim = "dkim-signature" in {k.lower() for k in headers}
    spf_pass, dkim_pass, dmarc_pass = ("pass" in spf or "pass" in auth), (dkim and "dkim=pass" in auth), ("dmarc=pass" in auth)
    if not spf_pass: findings.append("SPF absent ou échoué"); score += 0.20
    if not dkim_pass: findings.append("DKIM absent ou échoué"); score += 0.20
    if not dmarc_pass: findings.append("DMARC absent ou échoué"); score += 0.10

    from_addr, reply_to = parsed["from"], parsed["reply_to"]
    # FIX bug#1 : comparer les DOMAINES email (get_email_domain), pas les adresses brutes
    # avec display name, qui ne matchent jamais (ex: '"X" <a@d.com>' != '<a@d.com>').
    # IMPORTANT : ne jamais remplacer get_email_domain() par get_domain() ici (cf. docstring
    # de get_domain) — c'est exactement ce qui provoque un faux "Return-Path ≠ From" alors
    # que les deux adresses partagent le même domaine.
    if reply_to and from_addr:
        rtd, fd = get_email_domain(reply_to), get_email_domain(from_addr)
        if rtd and fd and rtd != fd:
            findings.append(f"Reply-To ({rtd}) ≠ From ({fd})"); score += 0.20

    return_path = parsed["return_path"]
    if return_path and from_addr:
        fd, rd = get_email_domain(from_addr), get_email_domain(return_path)
        if fd and rd and fd != rd:
            findings.append(f"Return-Path ({rd}) ≠ From ({fd})"); score += 0.15

    mailer = parsed["x_mailer"].lower()
    for sm in ["mailchimp","sendgrid","phpmailer","massmailer","bulk"]:
        if sm in mailer:
            findings.append(f"X-Mailer suspect : {parsed['x_mailer']}"); score += 0.10; break
    msg_id = parsed["message_id"]
    if not msg_id or not re.match(r"<.+@.+>", msg_id):
        findings.append("Message-ID absent ou invalide"); score += 0.10
    received  = str(headers.get("Received", ""))
    ips_found = list(set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", received)))
    return {"score": round(min(score, 1.0), 3), "spf_pass": spf_pass, "dkim_pass": dkim_pass,
            "dmarc_pass": dmarc_pass, "findings": findings, "ips_found": ips_found[:5]}

_whois_executor = ThreadPoolExecutor(max_workers=2)
def _whois_safe(domain):
    try: return _whois_executor.submit(whois.whois, domain).result(timeout=3)
    except Exception: return {}

def analyze_urls(urls):
    findings, suspicious, score = [], [], 0.0
    for url in urls[:10]:
        domain = get_domain(url)
        if not domain: continue
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                findings.append(f"TLD suspect : {domain}"); score += 0.15; suspicious.append(url); break
        domain_base = domain.split(".")[0]
        for brand in KNOWN_BRANDS:
            if 0 < Levenshtein.distance(domain_base, brand) <= 2:
                findings.append(f"Typosquatting : {domain} ≈ {brand}"); score += 0.25; suspicious.append(url); break
        if len(domain) > 40: findings.append(f"Domaine trop long : {domain}"); score += 0.10
        if domain.count("-") >= 3: findings.append(f"Beaucoup de tirets : {domain}"); score += 0.10
        if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            findings.append(f"IP directe : {url[:60]}"); score += 0.30; suspicious.append(url)
        url_norm = url.lower()
        if url_norm in urlhaus_set or url in urlhaus_set:
            findings.append(f"URLHaus blacklist : {url[:60]}"); score += 0.90; suspicious.append(url)
        if url_norm in openphish_set or url in openphish_set:
            findings.append(f"OpenPhish blacklist : {url[:60]}"); score += 0.90; suspicious.append(url)
        try:
            w = _whois_safe(domain)
            if w and w.get("creation_date"):
                creation = w["creation_date"]
                if isinstance(creation, list): creation = creation[0]
                if creation and (datetime.now() - creation).days < 30:
                    findings.append(f"Domaine très récent : {domain}"); score += 0.30; suspicious.append(url)
        except Exception: pass
    return {"score": round(min(score, 1.0), 3), "total_urls": len(urls),
            "suspicious": list(set(suspicious))[:5], "findings": findings}

def analyze_images(images):
    ocr_texts, findings, score = [], [], 0.0
    if len(images) > 3:
        findings.append(f"{len(images)} images — contournement filtre"); score += 0.15
    for img_data in images[:5]:
        try:
            raw = img_data["data"]
            if not raw: continue
            img = Image.open(BytesIO(raw))
            w, h = img.size
            if w <= 3 and h <= 3:
                findings.append("Pixel tracking"); score += 0.20; continue
            text = pytesseract.image_to_string(img, lang="eng+fra")
            if text.strip():
                ocr_texts.append(text.strip())
                kw = [k for k in ["verify","account","password","click","urgent","suspended","login","security","bank","credit card"] if k in text.lower()]
                if kw: findings.append(f"Mots-clés phishing image : {kw}"); score += 0.20
        except Exception: pass
    return {"score": round(min(score, 1.0), 3), "ocr_text": " ".join(ocr_texts)[:500], "images_count": len(images), "findings": findings}

def analyze_attachments(attachments: list) -> dict:
    findings, suspicious_hashes, score = [], [], 0.0
    DANGEROUS_EXT = {".exe",".bat",".cmd",".ps1",".vbs",".js",".jar",".scr",".pif",".com",".msi"}
    DOUBLE_EXT    = re.compile(r"\.(pdf|docx?|xlsx?|zip)\.(exe|bat|cmd|scr|ps1|vbs)$", re.I)
    
    for att in attachments:
        fname = att["filename"].lower()
        ct    = att["content_type"]
        
        # Double extension — vérification en premier, indépendante du contenu
        if DOUBLE_EXT.search(fname):
            findings.append(f"Double extension dangereuse : {att['filename']}")
            score += 0.50
        
        # Extension dangereuse simple
        for ext in DANGEROUS_EXT:
            if fname.endswith(ext):
                findings.append(f"Extension dangereuse : {att['filename']}")
                score += 0.40
                break
        
        # MIME mismatch — seulement si payload suffisant
        if att.get("data") and len(att["data"]) >= 32:
            try:
                import magic
                real_mime = magic.from_buffer(att["data"][:1024], mime=True)
                if real_mime and real_mime not in ct:
                    findings.append(f"MIME réel ({real_mime}) ≠ déclaré ({ct})")
                    score += 0.35
            except Exception:
                pass
        
        # Macros VBA
        if fname.endswith((".doc",".docx",".xls",".xlsx",".ppt",".pptx")):
            try:
                from oletools.olevba import VBA_Parser
                vba = VBA_Parser(att["filename"], data=att["data"])
                if vba.detect_vba_macros():
                    findings.append(f"Macros VBA : {att['filename']}")
                    score += 0.45
            except Exception:
                pass
        
        suspicious_hashes.append({
            "filename": att["filename"], "md5": att["md5"],
            "sha256": att["sha256"], "size": att["size"]
        })
    
    return {"score": round(min(score, 1.0), 3), "attachments_count": len(attachments),
            "suspicious_hashes": suspicious_hashes, "findings": findings}

def analyze_text(text):
    text_clean = clean_text(text)
    if not text_clean.strip():
        return {"bert_score":0.0,"lr_score":0.0,"score":0.0,"keywords":[]}
    inputs = tokenizer(text_clean, truncation=True, padding=True, max_length=256, return_tensors="pt")
    with torch.no_grad():
        logits = bert_model(**inputs).logits
    bert_score = float(torch.softmax(logits, dim=1).numpy()[0][1])
    lr_score   = float(lr_model.predict_proba(tfidf.transform([text_clean]))[0][1])
    keywords = [kw for kw in ["verify","account","password","click here","urgent","confirm","suspended","login",
                "update","security","limited","expire","winner","prize","claim","free","bank","credit card","wire transfer"]
                if kw in text.lower()]
    return {"bert_score": round(bert_score, 4), "lr_score": round(lr_score, 4),
            "score": round(bert_score * 0.6 + lr_score * 0.4, 4), "keywords": keywords}

def rag_search(text):
    if not RAG_OK:
        return {"techniques":[],"apt_groups":[],"campaigns":[],"live_iocs":[]}
    q_emb = embed_fn([text[:500]])
    def _query(col, n):
        if not col: return None
        try: return col.query(query_embeddings=q_emb, n_results=n)
        except Exception: return None
    def _parse(res, fields):
        if not res or not res["ids"][0]: return []
        out = []
        for i in range(len(res["ids"][0])):
            item = {"similarity": round(1 - res["distances"][0][i], 3)}
            for f in fields: item[f] = res["metadatas"][0][i].get(f, "")
            out.append(item)
        return out
    return {
        "techniques": _parse(_query(col_techniques, 3), ["tech_id","name","tactics"]),
        "apt_groups": _parse(_query(col_apt, 2),        ["group_id","name","aliases"]),
        "campaigns":  _parse(_query(col_ti, 2),         ["campaign","actor","technique","severity"]),
        "live_iocs":  _parse(_query(col_live, 2),       ["url","attack_type","brand_target"]) if col_live else [],
    }

def _call_llm(prompt):
    if llm_backend == "groq":
        resp = llm_client.chat.completions.create(model="llama-3.1-8b-instant",
            messages=[{"role":"user","content":prompt}], temperature=0.1, max_tokens=800)
        return resp.choices[0].message.content
    elif llm_backend == "gemini":
        return llm_client.generate_content(prompt).text
    return ""

def classify_verdict(score_global):
    """Seule source de vérité pour le verdict. Le LLM ne doit JAMAIS décider seul du
    label final — il peut se tromper ou halluciner (cf. cas 'SUSPECT' à 0.14).
    """
    if score_global >= SCORE_THRESHOLD_PHISHING:
        return "PHISHING"
    if score_global >= SCORE_THRESHOLD_SUSPECT:
        return "SUSPECT"
    return "LEGITIME"

def classify_confidence(score_global):
    """Confiance basée sur la distance du score aux seuils de bascule : un score loin
    des seuils (ex: 0.05 ou 0.95) est classé avec confiance haute ; un score proche
    d'une frontière (ex: 0.38 ou 0.68) est intrinsèquement ambigu -> confiance basse."""
    nearest_boundary = min(abs(score_global - SCORE_THRESHOLD_SUSPECT),
                           abs(score_global - SCORE_THRESHOLD_PHISHING))
    if nearest_boundary >= 0.15:
        return "haute"
    if nearest_boundary >= 0.07:
        return "moyenne"
    return "faible"

def _neutral_legitimate_report(score_global, header_r):
    """Rapport de repli, cohérent, pour un email jugé LEGITIME après override du verdict LLM.
    Evite de laisser une explication/recommandation 'phishing' résiduelle du LLM (bug#2)."""
    header_r = header_r or {}
    auth_bits = []
    if header_r.get("spf_pass"): auth_bits.append("SPF")
    if header_r.get("dkim_pass"): auth_bits.append("DKIM")
    if header_r.get("dmarc_pass"): auth_bits.append("DMARC")
    auth_txt = ", ".join(auth_bits) + " conformes" if auth_bits else "authentification incomplète"
    return {
        "explication": (f"Score global faible ({score_global:.2f}) — email jugé légitime. "
                        f"{auth_txt}. Aucun indicateur technique significatif de phishing détecté."),
        "recommandation": "Aucune action requise.",
        "indicateurs_cles": [],
        # Le RAG renvoie toujours le match MITRE le plus proche, même sans rapport réel
        # (recherche par similarité, pas de seuil). Sur un verdict LEGITIME, afficher
        # une technique/campagne n'a pas de sens et sème la confusion côté SOC.
        "campagne_probable": "Aucune",
        "technique_attck": "N/A",
    }

def generate_report(parsed, header_r, url_r, image_r, attach_r, text_r, rag_r, ti_r, score_global):
    top_tech     = rag_r["techniques"][0] if rag_r["techniques"] else {}
    top_campaign = rag_r["campaigns"][0]  if rag_r["campaigns"]  else {}
    top_apt      = rag_r["apt_groups"][0] if rag_r["apt_groups"] else {}
    all_findings = (header_r["findings"] + url_r["findings"] + image_r["findings"] + attach_r["findings"])
    iocs_detected = ti_r.get("iocs_detected", [])

    if not llm_client:
        verdict = classify_verdict(score_global)
        base = {"verdict": verdict, "confiance": classify_confidence(score_global),
                "score_final": score_global, "campagne_probable": top_campaign.get("campaign","Inconnue"),
                "technique_attck": f"{top_tech.get('tech_id','')} — {top_tech.get('name','N/A')}",
                "vecteur_attaque": "lien" if url_r["suspicious"] else "texte seul",
                "indicateurs_cles": all_findings[:5],
                "explication": f"Score {score_global:.2f}. {len(all_findings)} indicateurs. LLM indisponible.",
                "recommandation": "Bloquer et quarantaine." if verdict == "PHISHING" else
                                   ("Vérification manuelle." if verdict == "SUSPECT" else "Aucune action requise."),
                "iocs": {"urls_suspectes": url_r["suspicious"], "ips_malveillantes": header_r["ips_found"],
                         "hashes": [h["sha256"] for h in attach_r["suspicious_hashes"]]},
                "sigma_hint": url_r["suspicious"][0] if url_r["suspicious"] else ""}
        if verdict == "LEGITIME":
            base.update(_neutral_legitimate_report(score_global, header_r))
        return base

    urls_json   = _json.dumps(url_r["suspicious"])
    ips_json    = _json.dumps(header_r["ips_found"])
    hashes_json = _json.dumps([h["sha256"] for h in attach_r["suspicious_hashes"]])
    ti_block    = f"IoCs confirmés externes : {iocs_detected}" if iocs_detected else "Aucun IoC externe confirmé"

    prompt = f"""Tu es un analyste SOC expert en détection de phishing.

=== EMAIL ===
De      : {parsed.get("from","")}
Sujet   : {parsed.get("subject","")}
Extrait : {parsed.get("full_text","")[:300]}

=== SCORES ===
Headers : {header_r["score"]} | SPF={header_r["spf_pass"]} DKIM={header_r["dkim_pass"]} DMARC={header_r["dmarc_pass"]}
URLs    : {url_r["score"]} ({url_r["total_urls"]} URLs, {len(url_r["suspicious"])} suspectes)
OCR     : {image_r["score"]} | Attachments : {attach_r["score"]}
NLP     : BERT={text_r["bert_score"]} LR={text_r["lr_score"]}
TI      : {ti_r.get("score",0)} | Global : {score_global}

=== INDICATEURS ===
{chr(10).join(all_findings) if all_findings else "Aucun"}

=== THREAT INTEL EXTERNE ===
{ti_block}

=== RAG ===
MITRE   : {top_tech.get("tech_id","")} {top_tech.get("name","")} (sim={top_tech.get("similarity",0)})
APT     : {top_apt.get("name","")} (sim={top_apt.get("similarity",0)})
Campagne: {top_campaign.get("campaign","")} — {top_campaign.get("actor","")} (sim={top_campaign.get("similarity",0)})

IMPORTANT : le champ "verdict" DOIT être cohérent avec le score_global fourni ci-dessus
(< 0.35 -> LEGITIME, 0.35-0.65 -> SUSPECT, >= 0.65 -> PHISHING). Ne contredis jamais le score
dans "explication" ou "recommandation" : si le score indique un email légitime, dis-le clairement.

Réponds STRICTEMENT avec un JSON valide, sans texte avant/après, sans markdown :

{{"verdict": "PHISHING", "confiance": "haute", "score_final": {score_global}, "campagne_probable": "nom ou Aucune", "technique_attck": "T#### - nom", "vecteur_attaque": "lien", "indicateurs_cles": ["max 5, mentionne les hits VT/AbuseIPDB si presents"], "explication": "2-3 phrases SOC", "recommandation": "action", "iocs": {{"urls_suspectes": {urls_json}, "ips_malveillantes": {ips_json}, "hashes": {hashes_json}}}, "sigma_hint": "valeur"}}"""

    try:
        raw = _call_llm(prompt)
        raw = re.sub(r"```json|```", "", raw).strip()
        m   = re.search(r"\{.*\}", raw, re.DOTALL)
        result = _json.loads(m.group() if m else raw)

        # FIX bug#2 (durci) : le LLM ne décide plus JAMAIS seul du verdict ni de la
        # confiance — trop peu fiable (on a observé des verdicts "SUSPECT"/"haute"
        # à un score de 0.14). Le verdict/la confiance sont TOUJOURS recalculés à
        # partir du score_global. Le LLM ne fournit que le texte explicatif, la
        # campagne probable, la technique MITRE et les indicateurs.
        final_verdict = classify_verdict(score_global)
        llm_verdict    = result.get("verdict")
        result["verdict"]   = final_verdict
        result["confiance"] = classify_confidence(score_global)

        if final_verdict == "LEGITIME":
            # Le LLM peut avoir halluciné une explication "phishing" pour le verdict
            # qu'il avait initialement choisi : on la neutralise systématiquement,
            # pas seulement quand llm_verdict == "PHISHING".
            result.update(_neutral_legitimate_report(score_global, header_r))
        elif final_verdict == "SUSPECT" and llm_verdict == "PHISHING":
            # Le LLM était trop alarmiste par rapport au score : on garde son
            # explication (souvent encore utile) mais on adoucit la recommandation.
            result["recommandation"] = "Vérification manuelle recommandée avant action."

        return result
    except Exception as e:
        verdict = classify_verdict(score_global)
        base = {"verdict": verdict, "confiance": classify_confidence(score_global), "score_final": score_global,
                "explication": f"Erreur LLM : {str(e)[:100]}",
                "campagne_probable": top_campaign.get("campaign","N/A"),
                "technique_attck": f"{top_tech.get('tech_id','')} {top_tech.get('name','')}",
                "vecteur_attaque": "lien" if url_r["suspicious"] else "texte seul",
                "indicateurs_cles": all_findings[:5], "recommandation": "Vérification manuelle",
                "iocs": {"urls_suspectes": url_r["suspicious"], "ips_malveillantes": header_r["ips_found"],
                         "hashes": [h["sha256"] for h in attach_r["suspicious_hashes"]]},
                "sigma_hint": url_r["suspicious"][0] if url_r["suspicious"] else ""}
        if verdict == "LEGITIME":
            base.update(_neutral_legitimate_report(score_global, header_r))
        return base

# ══════════════════════════════════════════════════════════════
# GARDE-FOU DE COHÉRENCE (nouveau)
# ══════════════════════════════════════════════════════════════
def enforce_report_consistency(result: dict) -> dict:
    """Dernière ligne de défense, appelée juste après agent.run() dans les deux
    endpoints d'analyse, AVANT toute alerte SOC ou sauvegarde en DB.

    Pourquoi ce garde-fou existe : generate_report() ci-dessus recalcule déjà
    verdict/confiance depuis score_global et neutralise l'explication quand le
    verdict est LEGITIME. Mais ce recalcul ne protège que le chemin de code
    interne à generate_report(). Si l'orchestrateur (OrchestratorAgent, dans un
    fichier séparé qu'on ne contrôle pas ici) appelle generate_report autrement,
    met en cache un résultat, ou modifie le report après coup, une incohérence
    verdict/score/explication peut quand même ressortir de l'API (c'est
    exactement ce qui s'est produit sur le cas 'Confirmation de vos congés' :
    verdict LEGITIME à l'écran mais explication et recommandation de type
    phishing, et un finding Return-Path/From basé sur des domaines mal extraits).

    Ce garde-fou ne fait confiance à AUCUNE étape amont : il re-dérive tout
    depuis result['score_global'] et, si besoin, écrase le report avant qu'il
    ne parte en alerte SOC, en PDF, ou en base."""
    report = result.get("report", {}) or {}
    score_global = result.get("score_global", 0.0)

    correct_verdict    = classify_verdict(score_global)
    correct_confidence = classify_confidence(score_global)

    incoherent = (
        report.get("verdict") != correct_verdict or
        report.get("confiance") != correct_confidence
    )
    if incoherent:
        report["verdict"]   = correct_verdict
        report["confiance"] = correct_confidence

    if correct_verdict == "LEGITIME":
        header_r = (result.get("modules", {}) or {}).get("headers", {}) or {}
        report.update(_neutral_legitimate_report(score_global, header_r))

    result["report"] = report
    return result

def _mitre_to_tag(technique_attck):
    m = re.search(r"T(\d{4})(?:\.(\d{3}))?", technique_attck or "")
    if not m: return "attack.t1566"
    base = f"attack.t{m.group(1)}"
    return f"{base}.{m.group(2)}" if m.group(2) else base

def _tactic_tag(tech_id):
    TACTIC_MAP = {"T1566":"attack.initial_access","T1598":"attack.reconnaissance",
                  "T1556":"attack.credential_access","T1539":"attack.credential_access",
                  "T1204":"attack.execution","T1027":"attack.defense_evasion"}
    base = tech_id.split(".")[0] if tech_id else ""
    return TACTIC_MAP.get(base, "attack.initial_access")

def _level_from_score(score):
    if score >= 0.85: return "critical"
    if score >= 0.65: return "high"
    if score >= 0.40: return "medium"
    if score >= 0.20: return "low"
    return "informational"

def generate_sigma_rules(report, score_global, email_meta=None):
    email_meta = email_meta or {}
    rules = []
    level = _level_from_score(score_global)
    tech_id = (report.get("technique_attck","") or "").split(" ")[0].strip("—-").strip()
    tag_technique, tag_tactic = _mitre_to_tag(tech_id), _tactic_tag(tech_id)
    rule_date = datetime.now().strftime("%Y/%m/%d")
    iocs = report.get("iocs", {})
    urls_susp, ips_mal, hashes_mal = iocs.get("urls_suspectes",[]), iocs.get("ips_malveillantes",[]), iocs.get("hashes",[])
    common_tags = ["attack.phishing", tag_tactic, tag_technique]
    common_refs = [f"https://attack.mitre.org/techniques/{tech_id}"] if tech_id else []

    if urls_susp:
        domains = list(set([re.sub(r"^https?://","",u).split("/")[0] for u in urls_susp]))
        rules.append({"type":"proxy_network","data":{
            "title": f"Accès à un domaine de phishing détecté par DASEC ({report.get('campagne_probable','Inconnue')})",
            "id": str(uuid.uuid4()), "status":"experimental",
            "description": f"Connexion vers domaine malveillant. Score : {score_global:.2f}. Vecteur : {report.get('vecteur_attaque','lien')}.",
            "references": common_refs + ["https://www.virustotal.com"],
            "author":"DASEC Automated Pipeline","date":rule_date,"tags":common_tags,
            "logsource":{"category":"proxy"},
            "detection":{"selection":{"c-uri|contains": domains if len(domains)>1 else domains[0]},"condition":"selection"},
            "falsepositives":["Domaine réutilisé légitimement","Faux positif AV tiers"],"level":level}})

    sender, subject = email_meta.get("from",""), email_meta.get("subject","")
    if sender or subject:
        selection = {}
        if sender: selection["sender|contains"] = sender.split("@")[-1] if "@" in sender else sender
        if subject: selection["subject|contains"] = subject[:60]
        rules.append({"type":"mail_gateway","data":{
            "title": f"Email de phishing détecté par DASEC — {report.get('campagne_probable','Inconnue')}",
            "id": str(uuid.uuid4()), "status":"experimental",
            "description": f"Caractéristiques phishing : {', '.join(report.get('indicateurs_cles',[])[:3]) or 'analyse NLP'}. MITRE : {report.get('technique_attck','N/A')}.",
            "references": common_refs, "author":"DASEC Automated Pipeline","date":rule_date,"tags":common_tags,
            "logsource":{"category":"mail"}, "detection":{"selection":selection,"condition":"selection"},
            "falsepositives":["Email légitime — vérifier SPF/DKIM/DMARC"],"level":level}})

    if hashes_mal:
        rules.append({"type":"file_hash","data":{
            "title":"Pièce jointe malveillante détectée par DASEC (hash confirmé VirusTotal)",
            "id": str(uuid.uuid4()), "status":"experimental",
            "description": f"Hash confirmé malveillant par VirusTotal. Score : {score_global:.2f}.",
            "references": common_refs + ["https://www.virustotal.com"],
            "author":"DASEC Automated Pipeline","date":rule_date,"tags":common_tags+["attack.execution"],
            "logsource":{"category":"file_event"}, "detection":{"selection":{"Hashes|contains":hashes_mal},"condition":"selection"},
            "falsepositives":["Aucun connu"],"level":"critical"}})

    yaml_blocks = []
    for r in rules:
        clean = {k:v for k,v in r["data"].items() if v is not None}
        yaml_str = yaml.dump(clean, sort_keys=False, allow_unicode=True, default_flow_style=False, width=100)
        yaml_blocks.append(yaml_str)
        r["yaml"] = yaml_str
    combined = "\n---\n".join(yaml_blocks) if yaml_blocks else "# Aucune règle générée"
    return {"rules_count": len(rules), "rules": [{"type":r["type"],"yaml":r["yaml"]} for r in rules], "combined_yaml": combined}

def send_soc_alert(report, parsed, score):
    if not SLACK_TOKEN or score < SOC_THRESHOLD: return False
    try:
        from slack_sdk import WebClient
        client = WebClient(token=SLACK_TOKEN)
        verdict = report.get("verdict","?")
        emoji = "🚨" if verdict == "PHISHING" else "⚠️"
        msg = (f"{emoji} *DASEC — {verdict}*\n>Score : {score:.2f} | Confiance : {report.get('confiance','?')}\n"
               f">De : {parsed.get('from','')}\n>Sujet : {parsed.get('subject','')}\n"
               f">Campagne : {report.get('campagne_probable','N/A')}\n>Technique : {report.get('technique_attck','N/A')}\n"
               f">Action : {report.get('recommandation','N/A')}\n>Indicateurs : {', '.join(report.get('indicateurs_cles',[])[:3])}")
        client.chat_postMessage(channel=SLACK_CHANNEL, text=msg)
        return True
    except Exception as e:
        print(f"Slack error: {e}"); return False

def compute_global_score(header_r, url_r, image_r, attach_r, text_r, ti_r, mode="full"):
    if mode == "text_only":
        url_bonus = 0.10 if len(url_r["suspicious"]) > 0 else 0.0
        return round(
            text_r["score"]        * 0.30 +
            url_r["score"]         * 0.45 +
            ti_r.get("score", 0.0) * 0.20 +
            url_bonus, 4)
    # Mode full — augmente le poids attachments de 0.10 → 0.15
    return round(
        header_r["score"]          * 0.20 +
        text_r["score"]            * 0.20 +
        url_r["score"]             * 0.20 +
        attach_r["score"]          * 0.15 +   # était 0.10
        ti_r.get("score", 0.0)     * 0.15 +
        image_r["score"]           * 0.05 +
        (len(url_r["suspicious"]) > 0) * 0.05, 4)

# ══════════════════════════════════════════════════════════════
# FASTAPI
# ══════════════════════════════════════════════════════════════
app = FastAPI(title="DASEC — Phishing Detection API",
             description="Headers+URLs+OCR+Attachments+NLP+RAG+LLM+ThreatIntel+Sigma+SOC+SQLite+PDF", version="5.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class TextRequest(BaseModel):
    text: str
    subject: Optional[str] = ""
    sender: Optional[str] = ""

EMPTY_HEADER = {"score":0.0,"spf_pass":None,"dkim_pass":None,"dmarc_pass":None,"findings":[],"ips_found":[]}
EMPTY_IMAGE  = {"score":0.0,"ocr_text":"","images_count":0,"findings":[]}
EMPTY_ATTACH = {"score":0.0,"attachments_count":0,"suspicious_hashes":[],"findings":[]}

@app.get("/")
def root():
    return {"message":"DASEC v5.0","status":"running","rag":RAG_OK,"llm_backend":llm_backend or "none"}

@app.get("/health")
def health():
    return {
        "status":"ok","models":["distilbert","lr","sentence-transformers"],
        "rag_collections":{
            "mitre_techniques": col_techniques.count() if col_techniques else 0,
            "mitre_apt_groups": col_apt.count() if col_apt else 0,
            "threat_intel": col_ti.count() if col_ti else 0,
            "live_ioc_feeds": col_live.count() if col_live else 0,
        },
        "ioc_feeds":{"urlhaus":len(urlhaus_set),"openphish":len(openphish_set)},
        "threat_intel_apis":{"virustotal":bool(VT_API_KEY),"abuseipdb":bool(ABUSEIPDB_KEY)},
        "llm_backend":llm_backend or "none","soc_alert":bool(SLACK_TOKEN),"soc_threshold":SOC_THRESHOLD,
        "db_path": DB_PATH, "pdf_output_dir": PDF_OUTPUT_DIR,
    }

@app.post("/analyze/eml")
async def analyze_eml(file: UploadFile = File(...)):
    if not file.filename.endswith(".eml"):
        raise HTTPException(400, "Fichier .eml requis")
 
    raw    = await file.read()
    parsed = parse_eml(raw)
    all_urls = list(set(parsed["urls_in_html"] + parsed["urls_in_text"]))
 
    # Instancier l'agent
    agent = OrchestratorAgent(parsed=parsed, mode="full")
 
    # Lancer le pipeline orchestré
    result = agent.run(
        fn_headers    = analyze_headers,
        fn_urls       = analyze_urls,
        fn_images     = analyze_images,
        fn_attachments= analyze_attachments,
        fn_text       = analyze_text,
        fn_rag        = rag_search,
        fn_ti         = threat_intel_check,
        fn_report     = generate_report,
        fn_sigma      = generate_sigma_rules,
        EMPTY_HEADER  = EMPTY_HEADER,
        EMPTY_IMAGE   = EMPTY_IMAGE,
        EMPTY_ATTACH  = EMPTY_ATTACH,
        all_urls      = all_urls,
        full_text     = parsed["full_text"],
    )

    # GARDE-FOU : recalcule verdict/confiance/explication depuis score_global,
    # quoi que l'orchestrateur ait renvoyé. Doit tourner AVANT l'alerte SOC et
    # la sauvegarde, sinon une incohérence amont peut encore déclencher une
    # fausse alerte Slack ou polluer l'historique.
    result = enforce_report_consistency(result)
 
    # Alertes SOC
    alert_sent = send_soc_alert(result["report"], parsed, result["score_global"])
    result["alert_sent"] = alert_sent
 
    # Métadonnées email
    result["email_meta"] = {
        "from":        parsed["from"],
        "to":          parsed["to"],
        "reply_to":    parsed["reply_to"],
        "return_path": parsed["return_path"],
        "subject":     parsed["subject"],
        "date":        parsed["date"],
    }
 
    # Sauvegarde SQLite
    aid = save_analysis(
        result, mode="eml",
        sender=parsed["from"], subject=parsed["subject"],
        alert_sent=alert_sent,
    )
    result["analysis_id"] = aid
    return result

@app.post("/analyze/text")
async def analyze_text_endpoint(req: TextRequest):
    all_urls = extract_urls(req.text)
 
    # Parsed minimal compatible avec l'agent
    parsed_minimal = {
        "from":        req.sender or "",
        "reply_to":    "",
        "return_path": "",
        "to":          "",
        "subject":     req.subject or "",
        "date":        datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
        "full_text":   req.text,
        "images":      [],
        "attachments": [],
        "urls_in_html": [],
        "urls_in_text": all_urls,
        "headers":     {},
        "_ips_found":  [],
    }
 
    agent = OrchestratorAgent(parsed=parsed_minimal, mode="text_only")
 
    result = agent.run(
        fn_headers    = analyze_headers,
        fn_urls       = analyze_urls,
        fn_images     = analyze_images,
        fn_attachments= analyze_attachments,
        fn_text       = analyze_text,
        fn_rag        = rag_search,
        fn_ti         = threat_intel_check,
        fn_report     = generate_report,
        fn_sigma      = generate_sigma_rules,
        EMPTY_HEADER  = EMPTY_HEADER,
        EMPTY_IMAGE   = EMPTY_IMAGE,
        EMPTY_ATTACH  = EMPTY_ATTACH,
        all_urls      = all_urls,
        full_text     = req.text,
    )

    # GARDE-FOU (voir commentaire dans /analyze/eml)
    result = enforce_report_consistency(result)
 
    result["alert_sent"]  = False
    result["email_meta"]  = {
        "from":    req.sender or "",
        "subject": req.subject or "",
        "date":    parsed_minimal["date"],
    }
 
    aid = save_analysis(
        result, mode="text",
        sender=req.sender or "", subject=req.subject or "",
        alert_sent=False,
    )
    result["analysis_id"] = aid
    return result

@app.get("/history")
def history(limit: int = Query(20, ge=1, le=100), verdict: str = Query(None)):
    return get_recent_analyses(limit=limit, verdict_filter=verdict)

@app.get("/history/{analysis_id}")
def history_detail(analysis_id: str):
    row = get_analysis_by_id(analysis_id)
    if not row:
        raise HTTPException(404, f"Analyse {analysis_id} introuvable")
    row["iocs_detail"] = get_iocs_by_analysis(analysis_id)
    return row

@app.get("/stats")
def stats():
    return get_stats()

@app.get("/report/pdf/{analysis_id}")
def report_pdf(analysis_id: str):
    """Génère et retourne le rapport PDF d'une analyse déjà loggée en DB."""
    row = get_analysis_by_id(analysis_id)
    if not row:
        raise HTTPException(404, f"Analyse {analysis_id} introuvable")

    result = row["report_full"]
    result["analysis_id"] = analysis_id
    pdf_path = generate_pdf_report(result)

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"DASEC_report_{analysis_id[:8]}.pdf",
        headers={"Content-Disposition": f'attachment; filename="DASEC_report_{analysis_id[:8]}.pdf"'},
    )