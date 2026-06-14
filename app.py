
"""CogniShield AI
Psychological Threat Intelligence & Social Engineering Defense Agent

Single-file Streamlit application designed for deployment on Streamlit Cloud.
Features:
- Premium dashboard UI with dark/light modes
- Local hybrid threat analysis engine
- Optional Gemini and Hugging Face API integrations
- SQLite history with filters, charts, and exports
- File upload support for text, PDF, DOCX, images, and audio/transcripts
- Safe offline fallback when APIs are unavailable
"""

from __future__ import annotations

import base64
import csv
import dataclasses
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import html
import io
import json
import os
import random
import re
import sqlite3
import textwrap
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import requests
import streamlit as st
import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")

# Optional dependencies with graceful fallbacks
try:
    from PIL import Image
except Exception:  # pragma: no cover
    Image = None

try:
    import pdfplumber
except Exception:  # pragma: no cover
    pdfplumber = None

try:
    from docx import Document
except Exception:  # pragma: no cover
    Document = None

try:
    import pytesseract
except Exception:  # pragma: no cover
    pytesseract = None

try:
    import speech_recognition as sr
except Exception:  # pragma: no cover
    sr = None

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
except Exception:  # pragma: no cover
    A4 = None
    canvas = None


APP_NAME = "CogniShield AI"
DB_PATH = Path(os.getenv("COGNISHIELD_DB_PATH", ".cognishield_history.db"))

LIGHT_THEME = {
    "bg": "#eef9ff",
    "panel": "rgba(255,255,255,0.72)",
    "card": "rgba(255,255,255,0.86)",
    "text": "#0b2239",
    "muted": "#4d647a",
    "primary": "#1aa7ff",
    "primary_2": "#00d4ff",
    "border": "rgba(26, 167, 255, 0.22)",
    "shadow": "0 12px 40px rgba(10, 61, 101, 0.12)",
    "good": "#17a673",
    "warn": "#f5a524",
    "bad": "#f44336",
    "critical": "#8e24aa",
}

DARK_THEME = {
    "bg": "#06131f",
    "panel": "rgba(11,25,40,0.82)",
    "card": "rgba(15,32,49,0.92)",
    "text": "#eaf6ff",
    "muted": "#9db6cb",
    "primary": "#59d8ff",
    "primary_2": "#85fff2",
    "border": "rgba(89, 216, 255, 0.22)",
    "shadow": "0 18px 48px rgba(0,0,0,0.45)",
    "good": "#40e0a0",
    "warn": "#ffc857",
    "bad": "#ff7a90",
    "critical": "#d16bff",
}

THREAT_LEVELS = [
    ("Low", 0, 19),
    ("Moderate", 20, 39),
    ("High", 40, 69),
    ("Critical", 70, 100),
]

TACTIC_LIBRARY = {
    "urgency_manipulation": {
        "weight": 12,
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bwithin (?:1|2|5|10|15) (?:minutes|hours)\b",
            r"\blast chance\b",
            r"\bact now\b",
            r"\bverify now\b",
            r"\bfinal warning\b",
            r"\baccount will be closed\b",
        ],
        "summary": "Pressure to rush the victim into making a fast decision.",
    },
    "authority_pressure": {
        "weight": 10,
        "patterns": [
            r"\bceo\b",
            r"\bbank manager\b",
            r"\bit support\b",
            r"\bpolice\b",
            r"\btax officer\b",
            r"\blegal team\b",
            r"\bhr department\b",
            r"\badmin\b",
        ],
        "summary": "Pretending to be a trusted official or authority figure.",
    },
    "fear_based_wording": {
        "weight": 8,
        "patterns": [
            r"\bsuspended\b",
            r"\bblocked\b",
            r"\bpenalty\b",
            r"\blegal action\b",
            r"\bfraud detected\b",
            r"\bsecurity breach\b",
            r"\bvirus detected\b",
            r"\bunauthorized\b",
        ],
        "summary": "Using fear to force compliance and reduce critical thinking.",
    },
    "reward_bait": {
        "weight": 8,
        "patterns": [
            r"\bcongratulations\b",
            r"\byou have won\b",
            r"\bprize\b",
            r"\bfree gift\b",
            r"\bcashback\b",
            r"\binvestment opportunity\b",
            r"\bguaranteed profit\b",
        ],
        "summary": "Using reward, profit, or gifts to lure the target.",
    },
    "impersonation": {
        "weight": 12,
        "patterns": [
            r"\bgoogle support\b",
            r"\bmicrosoft support\b",
            r"\bamazon support\b",
            r"\bpaytm\b",
            r"\bphonepe\b",
            r"\bbank of\b",
            r"\bofficial account\b",
            r"\bcustomer care\b",
            r"\bverification team\b",
        ],
        "summary": "Impersonating a company, service, or known support channel.",
    },
    "credential_harvesting": {
        "weight": 16,
        "patterns": [
            r"\bpassword\b",
            r"\bpin\b",
            r"\botp\b",
            r"\bcvv\b",
            r"\blogin\b",
            r"\bsign in\b",
            r"\bverify your account\b",
            r"\bupdate credentials\b",
        ],
        "summary": "Trying to collect passwords, OTPs, PINs, or login details.",
    },
    "emotional_exploitation": {
        "weight": 8,
        "patterns": [
            r"\bhelp me\b",
            r"\bplease trust me\b",
            r"\bdon't tell anyone\b",
            r"\bsecret\b",
            r"\byou are my only hope\b",
            r"\bfamily emergency\b",
            r"\bneed your support\b",
        ],
        "summary": "Using emotional pressure, secrecy, or guilt to influence action.",
    },
    "link_suspicion": {
        "weight": 10,
        "patterns": [
            r"https?://",
            r"\bbit\.ly\b",
            r"\bgoo\.gl\b",
            r"\btinyurl\b",
            r"\bshort link\b",
            r"\bclick here\b",
            r"\bopen the link\b",
            r"\bdownload invoice\b",
        ],
        "summary": "A link or download is being used to move the victim out of view.",
    },
    "money_fraud": {
        "weight": 14,
        "patterns": [
            r"\bsend money\b",
            r"\bpayment\b",
            r"\btransfer\b",
            r"\bupi\b",
            r"\bqr code\b",
            r"\brefund\b",
            r"\breceive funds\b",
            r"\bbank details\b",
        ],
        "summary": "The message is trying to trigger a financial transaction.",
    },
    "otp_theft": {
        "weight": 18,
        "patterns": [
            r"\bshare otp\b",
            r"\btell me the otp\b",
            r"\bread the code\b",
            r"\bverification code\b",
            r"\bone time password\b",
            r"\bconfirm by otp\b",
        ],
        "summary": "An OTP theft attempt usually means immediate account compromise risk.",
    },
    "fake_verification": {
        "weight": 12,
        "patterns": [
            r"\bverify your identity\b",
            r"\breconfirm account\b",
            r"\bsecurity check\b",
            r"\bupdate information\b",
            r"\baccount validation\b",
        ],
        "summary": "A fake verification flow is often used to steal access or data.",
    },
    "social_pressure": {
        "weight": 8,
        "patterns": [
            r"\bdo not ignore\b",
            r"\beveryone is doing it\b",
            r"\byour account will be deleted\b",
            r"\bneed immediate response\b",
            r"\breply quickly\b",
        ],
        "summary": "Pressuring the user to conform, respond, or obey instantly.",
    },
    "coercion": {
        "weight": 10,
        "patterns": [
            r"\bif you don't\b",
            r"\botherwise\b",
            r"\byou must\b",
            r"\bcomply\b",
            r"\bconsequence\b",
            r"\bwe will escalate\b",
        ],
        "summary": "Coercive framing tries to replace choice with fear.",
    },
    "banking_impersonation": {
        "weight": 14,
        "patterns": [
            r"\bbank\b",
            r"\batm\b",
            r"\bdebit card\b",
            r"\bcredit card\b",
            r"\baccount number\b",
            r"\bkyc\b",
            r"\bnominee\b",
        ],
        "summary": "A banking impersonation or account-risk message.",
    },
    "job_offer_scam": {
        "weight": 9,
        "patterns": [
            r"\bwork from home\b",
            r"\beasy job\b",
            r"\bpart time\b",
            r"\binterview without interview\b",
            r"\bprocessing fee\b",
            r"\bjoin immediately\b",
        ],
        "summary": "A fake job offer often asks for money or personal details.",
    },
    "parcel_delivery_scam": {
        "weight": 9,
        "patterns": [
            r"\bparcel\b",
            r"\bcourier\b",
            r"\bdelivery failed\b",
            r"\bcustoms\b",
            r"\bpackage held\b",
            r"\baddress verification\b",
        ],
        "summary": "A parcel delivery pretext often contains malicious links or fees.",
    },
    "refund_scam": {
        "weight": 10,
        "patterns": [
            r"\brefund\b",
            r"\breverse payment\b",
            r"\bchargeback\b",
            r"\bmerchant error\b",
            r"\bconfirm to receive refund\b",
        ],
        "summary": "Refund scams push the victim into sharing payment details or OTP.",
    },
    "vishing_voice": {
        "weight": 10,
        "patterns": [
            r"\bcall me\b",
            r"\bvoice call\b",
            r"\bpress 1\b",
            r"\binteractive voice response\b",
            r"\brobotic voice\b",
        ],
        "summary": "Transcript cues that resemble vishing or voice-based social engineering.",
    },
    "ai_voice_scam": {
        "weight": 10,
        "patterns": [
            r"\bvoice cloned\b",
            r"\bdeepfake voice\b",
            r"\bhurry on the call\b",
            r"\bthis is your son\b",
            r"\btransfer funds now\b",
        ],
        "summary": "Voice impersonation or deepfake-style scam language.",
    },
}

SAFE_INDICATORS = [
    "official website",
    "published policy",
    "public support portal",
    "no urgency",
    "verify through known channel",
    "no request for otp",
    "no money requested",
    "clear context",
    "routine notification",
]


@dataclass
class AnalysisResult:
    input_text: str
    cleaned_text: str
    risk_score: int
    threat_level: str
    confidence: float
    manipulation_likelihood: int
    exposure_level: int
    anomaly_level: int
    tactic_counts: Dict[str, int]
    suspicious_phrases: List[str]
    safe_indicators: List[str]
    rationale: List[str]
    attacker_goal: str
    attack_stage: str
    recommendation_now: str
    what_attacker_wants: str
    do_not_do: List[str]
    safe_verification_steps: List[str]
    report_to: List[str]
    verdict: str
    uncertainty_note: str
    analyst_summary: str
    source_type: str = "text"
    analyst_notes: str = ""
    created_at: str = dataclasses.field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source_type TEXT,
            input_text TEXT NOT NULL,
            result_json TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            threat_level TEXT NOT NULL,
            tactic_summary TEXT NOT NULL,
            analyst_notes TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_record(result: AnalysisResult) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO analyses
        (created_at, source_type, input_text, result_json, risk_score, threat_level, tactic_summary, analyst_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.created_at,
            result.source_type,
            result.input_text,
            json.dumps(asdict(result), ensure_ascii=False),
            int(result.risk_score),
            result.threat_level,
            json.dumps(result.tactic_counts, ensure_ascii=False),
            result.analyst_notes,
        ),
    )
    conn.commit()
    conn.close()


def load_history(
    risk_level: str = "All",
    tactic_filter: str = "All",
    source_type: str = "All",
    query: str = "",
) -> pd.DataFrame:
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM analyses ORDER BY id DESC", conn)
    conn.close()

    if df.empty:
        return df

    df["created_at"] = pd.to_datetime(df["created_at"], errors="coerce")
    df["tactic_summary"] = df["tactic_summary"].fillna("{}")
    df["analyst_notes"] = df["analyst_notes"].fillna("")

    if risk_level != "All":
        df = df[df["threat_level"] == risk_level]
    if source_type != "All":
        df = df[df["source_type"] == source_type]
    if tactic_filter != "All":
        df = df[df["tactic_summary"].str.contains(re.escape(tactic_filter), case=False, na=False)]
    if query.strip():
        query_lower = query.lower()
        df = df[
            df["input_text"].str.lower().str.contains(query_lower, na=False)
            | df["result_json"].str.lower().str.contains(query_lower, na=False)
            | df["analyst_notes"].str.lower().str.contains(query_lower, na=False)
        ]
    return df


def delete_history_row(row_id: int) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM analyses WHERE id = ?", (row_id,))
    conn.commit()
    conn.close()


def clear_history() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM analyses")
    conn.commit()
    conn.close()


def theme_tokens() -> Dict[str, str]:
    dark_mode = st.session_state.get("dark_mode", False)
    return DARK_THEME if dark_mode else LIGHT_THEME


def apply_css() -> None:
    theme = theme_tokens()
    bg = theme["bg"]
    panel = theme["panel"]
    card = theme["card"]
    text = theme["text"]
    muted = theme["muted"]
    primary = theme["primary"]
    primary_2 = theme["primary_2"]
    border = theme["border"]
    shadow = theme["shadow"]

    st.markdown(
        f"""
        <style>
        .stApp {{
            background:
                radial-gradient(circle at top left, rgba(26,167,255,0.12), transparent 24%),
                radial-gradient(circle at bottom right, rgba(0,212,255,0.10), transparent 28%),
                linear-gradient(180deg, {bg}, {bg});
            color: {text};
        }}
        html, body, [class*="css"] {{
            font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }}
        .block-container {{
            padding-top: 1.1rem;
            padding-bottom: 2rem;
            max-width: 1450px;
        }}
        .cogni-hero {{
            background: linear-gradient(135deg, rgba(26,167,255,0.18), rgba(0,212,255,0.08));
            border: 1px solid {border};
            border-radius: 24px;
            padding: 1.1rem 1.2rem;
            box-shadow: {shadow};
            backdrop-filter: blur(18px);
        }}
        .cogni-title {{
            font-size: 2.1rem;
            font-weight: 800;
            letter-spacing: 0.3px;
            line-height: 1.1;
            margin-bottom: 0.25rem;
        }}
        .cogni-subtitle {{
            color: {muted};
            font-size: 0.98rem;
            line-height: 1.55;
        }}
        .pill {{
            display: inline-block;
            padding: 0.34rem 0.75rem;
            border-radius: 999px;
            border: 1px solid {border};
            background: {panel};
            margin-right: 0.45rem;
            margin-bottom: 0.35rem;
            font-size: 0.83rem;
        }}
        .status-dot {{
            display: inline-block;
            width: 9px;
            height: 9px;
            border-radius: 50%;
            margin-right: 0.45rem;
            background: {primary_2};
            box-shadow: 0 0 12px {primary_2};
        }}
        .glass-card {{
            background: {card};
            border: 1px solid {border};
            border-radius: 22px;
            padding: 1rem 1rem 0.85rem 1rem;
            box-shadow: {shadow};
            backdrop-filter: blur(16px);
            transition: all 0.25s ease;
        }}
        .glass-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 16px 42px rgba(0,0,0,0.18);
        }}
        .metric-card {{
            padding: 0.95rem 1rem;
            border-radius: 18px;
            border: 1px solid {border};
            background: linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.02));
            box-shadow: {shadow};
            min-height: 100px;
        }}
        .metric-label {{
            font-size: 0.82rem;
            color: {muted};
            text-transform: uppercase;
            letter-spacing: 0.09em;
            margin-bottom: 0.25rem;
        }}
        .metric-value {{
            font-size: 1.75rem;
            font-weight: 800;
            color: {text};
            line-height: 1.1;
        }}
        .metric-note {{
            font-size: 0.84rem;
            color: {muted};
            margin-top: 0.2rem;
        }}
        .scan-line {{
            height: 4px;
            border-radius: 999px;
            background: linear-gradient(90deg, transparent, {primary}, {primary_2}, transparent);
            animation: sweep 2.1s linear infinite;
            margin-top: 0.4rem;
            margin-bottom: 0.4rem;
        }}
        @keyframes sweep {{
            0% {{ opacity: 0.2; transform: translateX(-6%); }}
            50% {{ opacity: 1; }}
            100% {{ opacity: 0.2; transform: translateX(6%); }}
        }}
        .small-muted {{
            color: {muted};
            font-size: 0.88rem;
        }}
        .report-box {{
            border-left: 4px solid {primary};
            background: rgba(26,167,255,0.06);
            padding: 0.75rem 0.95rem;
            border-radius: 14px;
            margin-top: 0.5rem;
        }}
        .badge-safe {{
            color: #0d7a51;
            background: rgba(23,166,115,0.12);
            border: 1px solid rgba(23,166,115,0.25);
            border-radius: 999px;
            padding: 0.23rem 0.55rem;
            font-size: 0.79rem;
        }}
        .badge-warn {{
            color: #9a6700;
            background: rgba(245,165,36,0.12);
            border: 1px solid rgba(245,165,36,0.25);
            border-radius: 999px;
            padding: 0.23rem 0.55rem;
            font-size: 0.79rem;
        }}
        .badge-bad {{
            color: #a12c3f;
            background: rgba(244,67,54,0.12);
            border: 1px solid rgba(244,67,54,0.25);
            border-radius: 999px;
            padding: 0.23rem 0.55rem;
            font-size: 0.79rem;
        }}
        .badge-critical {{
            color: #7514a9;
            background: rgba(145, 45, 255, 0.13);
            border: 1px solid rgba(145, 45, 255, 0.24);
            border-radius: 999px;
            padding: 0.23rem 0.55rem;
            font-size: 0.79rem;
        }}
        .sidebar-note {{
            font-size: 0.86rem;
            color: {muted};
            line-height: 1.45;
        }}
        .stButton > button {{
            border-radius: 14px;
            border: 1px solid {border};
            background: linear-gradient(135deg, rgba(26,167,255,0.20), rgba(0,212,255,0.12));
            color: {text};
            padding: 0.55rem 0.9rem;
            transition: all 0.2s ease;
        }}
        .stButton > button:hover {{
            transform: translateY(-1px);
            border-color: rgba(26,167,255,0.45);
        }}
        .analysis-chip {{
            display: inline-block;
            margin: 0 0.38rem 0.35rem 0;
            padding: 0.25rem 0.55rem;
            border-radius: 999px;
            border: 1px solid {border};
            background: rgba(255,255,255,0.07);
            font-size: 0.8rem;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def set_defaults() -> None:
    defaults = {
        "dark_mode": False,
        "api_provider": "Local",
        "gemini_model": os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
        "hf_model": os.getenv("HF_MODEL", "distilbert-base-uncased-finetuned-sst-2-english"),
        "analysis_verbosity": "Balanced",
        "sensitivity": 55,
        "admin_mode": False,
        "last_result": None,
        "history_cache": [],
        "active_tab": "Overview",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def icon_for_level(level: str) -> str:
    return {"Low": "🟢", "Moderate": "🟠", "High": "🔴", "Critical": "🟣"}.get(level, "⚪")


def level_to_badge(level: str) -> str:
    if level == "Low":
        return "badge-safe"
    if level == "Moderate":
        return "badge-warn"
    if level == "High":
        return "badge-bad"
    return "badge-critical"


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def hash_text(text: str, settings_key: str = "") -> str:
    return hashlib.sha256((text + "|" + settings_key).encode("utf-8", errors="ignore")).hexdigest()


def extract_clean_text(text: str) -> str:
    text = text or ""
    text = text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def find_matches(text: str, patterns: List[str]) -> List[str]:
    matches: List[str] = []
    for pattern in patterns:
        for found in re.findall(pattern, text, flags=re.IGNORECASE):
            if isinstance(found, tuple):
                found = " ".join(found)
            if found and found not in matches:
                matches.append(str(found))
    return matches


def analyze_text_local(text: str, source_type: str = "text", analyst_notes: str = "") -> AnalysisResult:
    cleaned = extract_clean_text(text)
    lower_text = cleaned.lower()

    tactic_counts: Dict[str, int] = {}
    suspicious_phrases: List[str] = []
    rationale: List[str] = []
    total_risk = 0

    for tactic_name, tactic_data in TACTIC_LIBRARY.items():
        count = 0
        collected = []
        for pattern in tactic_data["patterns"]:
            matches = re.findall(pattern, lower_text, flags=re.IGNORECASE)
            if matches:
                count += len(matches)
                for m in matches:
                    if isinstance(m, tuple):
                        m = " ".join(m)
                    collected.append(str(m))
        if count:
            tactic_counts[tactic_name] = count
            total_risk += tactic_data["weight"] * min(3, count)
            rationale.append(f"{tactic_name.replace('_', ' ').title()} detected {count} time(s).")
            suspicious_phrases.extend(collected[:3])

    # Context modifiers
    has_link = bool(re.search(r"https?://|bit\.ly|tinyurl|goo\.gl|t\.me|wa\.me", lower_text))
    has_money = bool(re.search(r"\bupi\b|\bpay\b|\btransfer\b|\brefund\b|\bcash\b|\bbank\b", lower_text))
    has_otp = bool(re.search(r"\botp\b|\bcode\b|\bverification\b|\bpin\b", lower_text))
    has_urgency = "urgency_manipulation" in tactic_counts or "social_pressure" in tactic_counts
    has_impersonation = "impersonation" in tactic_counts or "authority_pressure" in tactic_counts

    if has_link:
        total_risk += 8
        rationale.append("Contains an external link or shortened link indicator.")
    if has_money:
        total_risk += 7
        rationale.append("Contains payment or money-transfer language.")
    if has_otp:
        total_risk += 10
        rationale.append("Contains credential or verification language that can be abused.")
    if has_urgency:
        total_risk += 6
    if has_impersonation:
        total_risk += 6

    safe_hits = [s for s in SAFE_INDICATORS if s in lower_text]
    if safe_hits:
        total_risk -= 7
        rationale.append("Some language looks routine or verification-based rather than coercive.")

    # Linguistic modifiers
    word_count = max(1, len(re.findall(r"\b\w+\b", cleaned)))
    punctuation_pressure = len(re.findall(r"[!]{2,}|[?]{2,}|[A-Z]{4,}", text))
    total_risk += min(8, punctuation_pressure * 2)

    # If the message is very short and contains one strong indicator, weight it up.
    if word_count < 25 and (has_otp or has_money or has_link):
        total_risk += 7
        rationale.append("Short, direct message with a high-value scam trigger can be especially risky.")

    # Neutral content lower risk
    if not tactic_counts:
        total_risk -= 8
        rationale.append("No strong scam indicators were found.")

    total_risk = int(clamp(total_risk, 0, 100))

    if total_risk < 20:
        threat_level = "Low"
    elif total_risk < 40:
        threat_level = "Moderate"
    elif total_risk < 70:
        threat_level = "High"
    else:
        threat_level = "Critical"

    # Confidence is higher when there are more exact matches and consistent patterns.
    match_strength = sum(tactic_counts.values())
    confidence = clamp((25 + match_strength * 10 + min(20, len(suspicious_phrases) * 3) + (12 if has_link else 0)) / 1.2, 0, 100)
    if not tactic_counts:
        confidence = max(confidence, 42)
    if total_risk >= 70:
        confidence = min(96, confidence + 8)

    manipulation_likelihood = int(clamp(total_risk + (8 if has_urgency else 0) + (8 if has_impersonation else 0) - (8 if safe_hits else 0)))
    exposure_level = int(clamp(total_risk * 0.9 + (10 if has_link else 0)))
    anomaly_level = int(clamp((len(tactic_counts) * 12) + (10 if len(cleaned) < 35 else 0) + (8 if punctuation_pressure else 0)))

    if total_risk >= 70:
        attacker_goal = "Capture credentials, transfer money, or force an unsafe action immediately."
        attack_stage = "Active coercion / credential harvesting"
        recommendation_now = "Stop engaging, verify through a known official channel, and do not click links or share codes."
        verdict = "This message is highly suspicious and should be treated as a likely scam or impersonation attempt."
        uncertainty_note = "Confidence is strong enough to recommend urgent caution."
    elif total_risk >= 40:
        attacker_goal = "Push the recipient toward a fast, low-verification response."
        attack_stage = "Pretexting / persuasion"
        recommendation_now = "Pause, verify sender identity separately, and look for mismatched links, payments, or OTP requests."
        verdict = "This message has meaningful scam signals and deserves careful verification."
        uncertainty_note = "There is enough signal to warrant caution, even if the message is not fully malicious."
    elif total_risk >= 20:
        attacker_goal = "Create mild pressure or redirect attention."
        attack_stage = "Suspicion building"
        recommendation_now = "Check the sender, inspect the link destination, and avoid sharing private information until verified."
        verdict = "This message has some suspicious cues but is not conclusive."
        uncertainty_note = "Some indicators may be context-dependent."
    else:
        attacker_goal = "Likely routine communication, with little obvious manipulation."
        attack_stage = "Normal / low-risk communication"
        recommendation_now = "No immediate concern; still avoid sharing secrets or clicking unknown links."
        verdict = "This message appears low risk or neutral."
        uncertainty_note = "Low-risk messages can still hide risk in missing context, so stay alert."

    # Build defense guidance
    do_not_do = [
        "Do not share OTPs, PINs, CVV, or passwords.",
        "Do not click suspicious links or open unexpected attachments.",
        "Do not call numbers provided only inside the suspicious message.",
    ]
    safe_verification_steps = [
        "Open the official app or website yourself instead of using the message link.",
        "Call the company or sender using a number you already trust.",
        "Ask for a written confirmation from the official support channel.",
    ]
    report_to = [
        "Your bank or service provider's official fraud channel",
        "Your organisation's IT / security team, if this is work-related",
        "Local cybercrime reporting channel if money or identity theft is involved",
    ]

    if threat_level in {"High", "Critical"}:
        safe_verification_steps.append("If money or account access is involved, freeze the action until verified.")
        report_to.append("Law enforcement or cybercrime portal, if harm has already started")

    if safe_hits and not tactic_counts and total_risk < 20:
        analyst_summary = (
            "The message reads like routine or informational communication. "
            "No strong manipulation pattern appears, and the language does not strongly suggest scam intent."
        )
    else:
        analyst_summary = (
            "Local intelligence found a mix of tactic signals, context markers, and pressure language. "
            "The main risk is whether the sender is pushing you to move quickly, reveal sensitive data, or leave the trusted channel."
        )

    safe_indicators = safe_hits[:5]
    suspicious_phrases = list(dict.fromkeys([p for p in suspicious_phrases if p.strip()][:10]))

    return AnalysisResult(
        input_text=text,
        cleaned_text=cleaned,
        risk_score=total_risk,
        threat_level=threat_level,
        confidence=float(round(confidence, 1)),
        manipulation_likelihood=manipulation_likelihood,
        exposure_level=exposure_level,
        anomaly_level=anomaly_level,
        tactic_counts=tactic_counts,
        suspicious_phrases=suspicious_phrases,
        safe_indicators=safe_indicators,
        rationale=rationale[:8],
        attacker_goal=attacker_goal,
        attack_stage=attack_stage,
        recommendation_now=recommendation_now,
        what_attacker_wants=attacker_goal,
        do_not_do=do_not_do,
        safe_verification_steps=safe_verification_steps,
        report_to=report_to,
        verdict=verdict,
        uncertainty_note=uncertainty_note,
        analyst_summary=analyst_summary,
        source_type=source_type,
        analyst_notes=analyst_notes,
    )


def safe_join_phrases(phrases: List[str]) -> str:
    return ", ".join([p for p in phrases if p]) if phrases else "None detected"


def highlight_text(text: str, phrases: List[str]) -> str:
    highlighted = html.escape(text)
    for phrase in sorted(set(phrases), key=len, reverse=True):
        if not phrase:
            continue
        escaped_phrase = re.escape(html.escape(phrase))
        highlighted = re.sub(
            escaped_phrase,
            lambda m: f'<mark style="background:rgba(245,165,36,0.35);color:inherit;padding:0 0.12rem;border-radius:4px">{m.group(0)}</mark>',
            highlighted,
            flags=re.IGNORECASE,
        )
    highlighted = highlighted.replace("\n", "<br>")
    return highlighted


def build_gauge(value: float, title: str, color: str) -> go.Figure:
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=value,
            number={"font": {"size": 28}},
            title={"text": title},
            gauge={
                "axis": {"range": [0, 100], "tickwidth": 1},
                "bar": {"color": color},
                "bgcolor": "rgba(0,0,0,0)",
                "borderwidth": 1,
                "bordercolor": "rgba(120,120,120,0.25)",
                "steps": [
                    {"range": [0, 25], "color": "rgba(23,166,115,0.12)"},
                    {"range": [25, 50], "color": "rgba(245,165,36,0.14)"},
                    {"range": [50, 75], "color": "rgba(244,67,54,0.14)"},
                    {"range": [75, 100], "color": "rgba(145,45,255,0.16)"},
                ],
            },
        )
    )
    fig.update_layout(
        height=240,
        margin=dict(l=18, r=18, t=32, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme_tokens()["text"]),
    )
    return fig


def build_radar(tactic_counts: Dict[str, int]) -> go.Figure:
    categories = [
        "urgency_manipulation",
        "authority_pressure",
        "credential_harvesting",
        "impersonation",
        "link_suspicion",
        "money_fraud",
        "emotional_exploitation",
        "otp_theft",
    ]
    values = [min(5, tactic_counts.get(cat, 0) * 1.5) for cat in categories]
    values += values[:1]
    categories += categories[:1]
    fig = go.Figure()
    fig.add_trace(
        go.Scatterpolar(r=values, theta=categories, fill="toself", name="Threat Profile")
    )
    fig.update_layout(
        height=330,
        margin=dict(l=20, r=20, t=25, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        polar=dict(
            radialaxis=dict(visible=True, range=[0, 5]),
            bgcolor="rgba(0,0,0,0)",
        ),
        showlegend=False,
        font=dict(color=theme_tokens()["text"]),
    )
    return fig


def build_history_trends(df: pd.DataFrame) -> Tuple[Optional[go.Figure], Optional[go.Figure]]:
    if df.empty:
        return None, None
    df2 = df.copy()
    df2["created_at"] = pd.to_datetime(df2["created_at"], errors="coerce")
    df2 = df2.dropna(subset=["created_at"])
    if df2.empty:
        return None, None

    df2["date"] = df2["created_at"].dt.date.astype(str)

    line_fig = go.Figure()
    line_fig.add_trace(
        go.Scatter(
            x=df2["created_at"],
            y=df2["risk_score"],
            mode="lines+markers",
            name="Risk",
        )
    )
    line_fig.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        yaxis=dict(range=[0, 100]),
        font=dict(color=theme_tokens()["text"]),
    )

    level_counts = df2["threat_level"].value_counts().reindex(["Low", "Moderate", "High", "Critical"]).fillna(0)
    bar_fig = go.Figure(
        go.Bar(
            x=level_counts.index.tolist(),
            y=level_counts.values.tolist(),
            marker=dict(
                line=dict(width=0),
            ),
        )
    )
    bar_fig.update_layout(
        height=280,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme_tokens()["text"]),
    )
    return line_fig, bar_fig


def build_heatmap(df: pd.DataFrame) -> Optional[go.Figure]:
    if df.empty:
        return None
    rows = []
    for _, row in df.iterrows():
        try:
            tactics = json.loads(row.get("tactic_summary", "{}"))
        except Exception:
            tactics = {}
        for tactic, count in tactics.items():
            rows.append(
                {
                    "date": pd.to_datetime(row.get("created_at"), errors="coerce"),
                    "tactic": tactic,
                    "count": count,
                }
            )
    if not rows:
        return None
    temp = pd.DataFrame(rows).dropna(subset=["date"])
    if temp.empty:
        return None
    temp["day"] = temp["date"].dt.date.astype(str)
    pivot = temp.pivot_table(index="tactic", columns="day", values="count", aggfunc="sum", fill_value=0)
    fig = go.Figure(
        data=go.Heatmap(
            z=pivot.values,
            x=pivot.columns.tolist(),
            y=pivot.index.tolist(),
            colorscale="Blues",
        )
    )
    fig.update_layout(
        height=max(260, 24 * len(pivot.index) + 120),
        margin=dict(l=10, r=10, t=25, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=theme_tokens()["text"]),
    )
    return fig


def render_metric(label: str, value: str, note: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{html.escape(label)}</div>
            <div class="metric-value">{html.escape(value)}</div>
            <div class="metric-note">{html.escape(note)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def connection_status_badge(name: str, is_active: bool, detail: str) -> None:
    cls = "badge-safe" if is_active else "badge-warn"
    dot = "🟢" if is_active else "🟠"
    st.markdown(
        f"<span class='{cls}'>{dot} {html.escape(name)} — {html.escape(detail)}</span>",
        unsafe_allow_html=True,
    )


def get_gemini_api_url(model_name: str) -> str:
    model_name = model_name or "gemini-1.5-flash"
    return f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent"


def call_gemini_api(api_key: str, model_name: str, prompt: str, timeout: int = 25) -> Optional[str]:
    if not api_key:
        return None
    url = get_gemini_api_url(model_name)
    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.15,
            "topP": 0.95,
            "topK": 40,
            "maxOutputTokens": 900,
        },
    }
    try:
        resp = requests.post(url, params={"key": api_key}, json=payload, timeout=timeout)
        if resp.status_code >= 400:
            return None
        data = resp.json()
        candidates = data.get("candidates", [])
        if not candidates:
            return None
        parts = candidates[0].get("content", {}).get("parts", [])
        texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
        return "\n".join(t for t in texts if t).strip() or None
    except Exception:
        return None


def call_huggingface_api(api_key: str, model_name: str, text: str, timeout: int = 25) -> Optional[Dict[str, Any]]:
    if not api_key:
        return None
    url = f"https://api-inference.huggingface.co/models/{model_name}"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {"inputs": text[:5000]}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if resp.status_code >= 400:
            return None
        return resp.json()
    except Exception:
        return None


def build_ai_prompt(result: AnalysisResult) -> str:
    tactic_summary = ", ".join(
        f"{k.replace('_', ' ')}={v}" for k, v in sorted(result.tactic_counts.items(), key=lambda x: x[0])
    ) or "none"
    return f"""
You are CogniShield AI, a cybersecurity analyst specializing in social engineering defense.
Write a compact analyst-style summary with:
1) threat assessment,
2) likely attacker goal,
3) why it looks suspicious or safe,
4) recommended action now,
5) confidence caveat if needed.

Input message:
{result.cleaned_text}

Local engine findings:
Risk score: {result.risk_score}/100
Threat level: {result.threat_level}
Confidence: {result.confidence}%
Detected tactics: {tactic_summary}
Suspicious phrases: {", ".join(result.suspicious_phrases) if result.suspicious_phrases else "none"}

Style: professional, concise, direct, and specific.
Do not give unsafe operational advice to an attacker.
"""


def enhance_with_ai(result: AnalysisResult) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
    gemini_key = st.session_state.get("gemini_api_key", os.getenv("GEMINI_API_KEY", "")).strip()
    gemini_model = st.session_state.get("gemini_model", os.getenv("GEMINI_MODEL", "gemini-1.5-flash")).strip()
    hf_key = st.session_state.get("hf_api_key", os.getenv("HF_API_KEY", "")).strip()
    hf_model = st.session_state.get("hf_model", os.getenv("HF_MODEL", "distilbert-base-uncased-finetuned-sst-2-english")).strip()

    prompt = build_ai_prompt(result)
    gemini_text = call_gemini_api(gemini_key, gemini_model, prompt) if gemini_key else None

    hf_result = call_huggingface_api(hf_key, hf_model, result.cleaned_text) if hf_key else None
    return prompt, gemini_text, hf_result


def summarize_hf_response(hf_result: Optional[Dict[str, Any]]) -> str:
    if not hf_result:
        return "No Hugging Face output available."
    try:
        if isinstance(hf_result, list) and hf_result:
            first = hf_result[0]
            if isinstance(first, list):
                labels = ", ".join(f"{x.get('label')}: {x.get('score', 0):.2f}" for x in first[:3])
                return f"HF classifier output: {labels}"
            if isinstance(first, dict):
                return f"HF output: {first}"
        return f"HF output: {hf_result}"
    except Exception:
        return "Hugging Face output could not be parsed."


def detect_source_type_from_name(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}:
        return "image"
    if ext in {".wav", ".mp3", ".m4a", ".flac", ".aac", ".ogg"}:
        return "audio"
    if ext == ".pdf":
        return "pdf"
    if ext == ".docx":
        return "docx"
    return "text"


def extract_text_from_uploaded_file(uploaded_file) -> Tuple[str, str]:
    name = uploaded_file.name
    ext = Path(name).suffix.lower()
    raw = uploaded_file.getvalue()
    source_type = detect_source_type_from_name(name)

    if ext in {".txt", ".csv", ".log", ".json"}:
        try:
            return raw.decode("utf-8", errors="ignore"), source_type
        except Exception:
            return raw.decode(errors="ignore"), source_type

    if ext == ".pdf":
        if pdfplumber is not None:
            try:
                text_chunks = []
                with pdfplumber.open(io.BytesIO(raw)) as pdf:
                    for page in pdf.pages[:30]:
                        text_chunks.append(page.extract_text() or "")
                return "\n".join(text_chunks).strip(), source_type
            except Exception:
                pass
        return "PDF text extraction unavailable. Try the preview or OCR pathway.", source_type

    if ext == ".docx" and Document is not None:
        try:
            doc = Document(io.BytesIO(raw))
            paragraphs = [p.text for p in doc.paragraphs]
            return "\n".join(paragraphs).strip(), source_type
        except Exception:
            return "DOCX extraction failed.", source_type

    if source_type == "image":
        if Image is None:
            return "Image support unavailable. Install Pillow for image preview/OCR.", source_type
        try:
            image = Image.open(io.BytesIO(raw))
            if pytesseract is not None:
                try:
                    extracted = pytesseract.image_to_string(image)
                    if extracted.strip():
                        return extracted, source_type
                except Exception:
                    pass
            return "Image uploaded. OCR is unavailable or returned no readable text.", source_type
        except Exception:
            return "Image could not be read.", source_type

    if source_type == "audio":
        if sr is None:
            return "Audio file uploaded. Speech-to-text is unavailable; paste the transcript manually.", source_type
        try:
            temp_path = Path("._cognishield_audio")
            temp_path.write_bytes(raw)
            recognizer = sr.Recognizer()
            with sr.AudioFile(str(temp_path)) as source:
                audio_data = recognizer.record(source)
            try:
                text = recognizer.recognize_google(audio_data)
            except Exception:
                text = ""
            temp_path.unlink(missing_ok=True)
            return text or "Audio uploaded, but transcription failed. Paste a transcript for analysis.", source_type
        except Exception:
            return "Audio transcription unavailable. Paste a transcript for analysis.", source_type

    return raw.decode("utf-8", errors="ignore"), source_type


def render_status_bar(result: Optional[AnalysisResult]) -> None:
    if result is None:
        st.markdown('<div class="scan-line"></div>', unsafe_allow_html=True)
        return
    st.markdown('<div class="scan-line"></div>', unsafe_allow_html=True)


def source_label(source_type: str) -> str:
    return {
        "text": "Text",
        "pdf": "PDF",
        "docx": "DOCX",
        "image": "Image",
        "audio": "Audio",
    }.get(source_type, "Text")


def build_report_text(result: AnalysisResult, ai_text: str = "", hf_text: str = "") -> str:
    tactics = "\n".join([f"- {k.replace('_', ' ').title()}: {v}" for k, v in result.tactic_counts.items()]) or "- None"
    suspicious = "\n".join([f"- {x}" for x in result.suspicious_phrases]) or "- None"
    safe = "\n".join([f"- {x}" for x in result.safe_indicators]) or "- None"
    do_not = "\n".join([f"- {x}" for x in result.do_not_do])
    verify = "\n".join([f"- {x}" for x in result.safe_verification_steps])
    reports = "\n".join([f"- {x}" for x in result.report_to])

    return textwrap.dedent(
        f"""
        CogniShield AI Incident Report
        Generated: {result.created_at}

        Risk Score: {result.risk_score}/100
        Threat Level: {result.threat_level}
        Confidence: {result.confidence}%

        Verdict:
        {result.verdict}

        Analyst Summary:
        {result.analyst_summary}

        Suspicious Phrases:
        {suspicious}

        Detected Tactics:
        {tactics}

        Safe Indicators:
        {safe}

        What the Attacker Wants:
        {result.what_attacker_wants}

        Recommended Action Now:
        {result.recommendation_now}

        Do Not Do:
        {do_not}

        Safe Verification Steps:
        {verify}

        Report This To:
        {reports}

        Rationale:
        - {'; '.join(result.rationale) if result.rationale else 'No strong indicators were found.'}

        AI Enrichment:
        Gemini:
        {ai_text or 'Unavailable'}

        Hugging Face:
        {hf_text or 'Unavailable'}
        """
    ).strip()


def create_pdf_report(result: AnalysisResult, report_text: str) -> Optional[bytes]:
    if canvas is None or A4 is None:
        return None
    try:
        buffer = io.BytesIO()
        pdf = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        y = height - 48
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(42, y, "CogniShield AI Incident Report")
        y -= 28
        pdf.setFont("Helvetica", 10)
        for line in report_text.splitlines():
            if y < 42:
                pdf.showPage()
                y = height - 42
                pdf.setFont("Helvetica", 10)
            pdf.drawString(42, y, line[:110])
            y -= 13
        pdf.save()
        buffer.seek(0)
        return buffer.getvalue()
    except Exception:
        return None


def sample_cases() -> Dict[str, str]:
    return {
        "Urgent OTP Scam": "Your bank account will be blocked in 10 minutes. Share the OTP now to verify your identity.",
        "Parcel Delivery Scam": "Delivery failed. Click the link to pay customs and confirm your address immediately.",
        "Safe Message": "Please review the official policy posted on our public support portal. No action needed now.",
        "Fake Support": "Hello, this is Microsoft support. We detected a breach. Reply with your login code so we can help.",
        "Refund Trap": "You are eligible for a refund. Please confirm your UPI and CVV so we can process it quickly.",
    }


def render_metric_grid(result: AnalysisResult) -> None:
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        render_metric("Risk Score", f"{result.risk_score}/100", "Weighted local threat score")
    with c2:
        render_metric("Threat Level", result.threat_level, "Overall severity")
    with c3:
        render_metric("Confidence", f"{result.confidence:.1f}%", "Model certainty")
    with c4:
        render_metric("Manipulation", f"{result.manipulation_likelihood}/100", "Pressure intensity")
    with c5:
        render_metric("Exposure", f"{result.exposure_level}/100", "Potential harm if trusted")
    with c6:
        render_metric("Anomaly", f"{result.anomaly_level}/100", "Behavioral oddity")


def render_hero() -> None:
    st.markdown(
        f"""
        <div class="cogni-hero">
            <div class="cogni-title">CogniShield AI</div>
            <div class="cogni-subtitle">
                Psychological Threat Intelligence & Social Engineering Defense Agent
                built for scam detection, manipulation analysis, and safe verification guidance.
                <br><strong>Submitted By: Ravikant Arya</strong>
            </div>
            <div style="margin-top:0.8rem">
                <span class="pill"><span class="status-dot"></span>Local Engine Active</span>
                <span class="pill"><span class="status-dot"></span>Gemini Pro Connected</span>
                <span class="pill"><span class="status-dot"></span>Hugging Face Scanner Online</span>
                <span class="pill">Light Blue + Cyan Theme</span>
            </div>
            <div class="scan-line"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_overview(result: Optional[AnalysisResult]) -> None:
    render_hero()
    st.write("")
    left, right = st.columns([1.25, 0.85], gap="large")
    with left:
        st.markdown(
            """
            <div class="glass-card">
            <div style="font-size:1.05rem;font-weight:700;margin-bottom:0.25rem;">What this agent does</div>
            <div class="small-muted">
            It reviews messages, transcripts, screenshots, and documents to detect phishing, impersonation,
            urgency pressure, OTP theft, fake support language, financial fraud, and other psychological manipulation patterns.
            It explains the attack style in plain English and gives safe next steps.
            </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write("")
        if result:
            render_metric_grid(result)
        else:
            c1, c2, c3 = st.columns(3)
            with c1:
                render_metric("Risk Score", "—", "Run an analysis to see live metrics")
            with c2:
                render_metric("Threat Level", "Idle", "Waiting for input")
            with c3:
                render_metric("Confidence", "—", "Model certainty will appear here")

        st.write("")
        if result:
            col_a, col_b = st.columns([1.1, 0.9], gap="large")
            with col_a:
                st.plotly_chart(build_gauge(result.risk_score, "Threat Severity", theme_tokens()["primary"]), use_container_width=True)
            with col_b:
                st.plotly_chart(build_radar(result.tactic_counts), use_container_width=True)
        else:
            st.info("Use the Message Analyzer tab to inspect a suspicious message, screenshot, transcript, or file.")

    with right:
        st.markdown(
            """
            <div class="glass-card">
                <div style="font-size:1.05rem;font-weight:700;margin-bottom:0.25rem;">Live Intelligence Feed</div>
                <div class="small-muted">Mock threat feed for demo and portfolio use.</div>
                <div class="report-box">
                    <strong>Alert:</strong> Brand impersonation messages spiking around fake support cases.
                </div>
                <div class="report-box">
                    <strong>Alert:</strong> Parcel delivery scams frequently request payment or OTP verification.
                </div>
                <div class="report-box">
                    <strong>Alert:</strong> Screenshot fraud often hides tiny edits in balance, timestamp, or UPI IDs.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write("")
        st.markdown(
            """
            <div class="glass-card">
                <div style="font-size:1.05rem;font-weight:700;margin-bottom:0.25rem;">Security Posture</div>
                <div class="small-muted">Current engine status and quick readiness indicators.</div>
                <div style="margin-top:0.6rem;">
                    <span class="analysis-chip">Rules: Active</span>
                    <span class="analysis-chip">History: Enabled</span>
                    <span class="analysis-chip">Exports: Ready</span>
                    <span class="analysis-chip">Offline Mode: Supported</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_analysis_tab() -> None:
    st.subheader("Message Analyzer")
    st.caption("Paste a message, upload a file, or load a sample case. The engine works even without external APIs.")
    sample_choice = st.selectbox("Demo presets", ["— Select a sample —"] + list(sample_cases().keys()))
    if sample_choice != "— Select a sample —":
        st.session_state["analysis_input"] = sample_cases()[sample_choice]

    uploaded_file = st.file_uploader(
        "Upload text, PDF, DOCX, image, or audio/transcript file",
        type=["txt", "pdf", "docx", "png", "jpg", "jpeg", "webp", "bmp", "gif", "wav", "mp3", "m4a", "flac", "aac", "ogg"],
    )
    analyst_notes = st.text_area("Analyst notes", value=st.session_state.get("analyst_notes", ""), height=90, placeholder="Add internal notes, context, or case details.")
    st.session_state["analyst_notes"] = analyst_notes

    if uploaded_file is not None:
        extracted_text, source_type = extract_text_from_uploaded_file(uploaded_file)
        st.session_state["uploaded_text"] = extracted_text
        st.session_state["uploaded_source_type"] = source_type
        st.info(f"Detected source type: {source_label(source_type)}")
        with st.expander("Preview extracted content", expanded=False):
            st.code(extracted_text[:8000] if extracted_text else "(No text extracted yet)")
    else:
        source_type = st.session_state.get("uploaded_source_type", "text")

    user_text = st.text_area(
        "Analysis input",
        value=st.session_state.get("analysis_input", st.session_state.get("uploaded_text", "")),
        height=210,
        placeholder="Paste the message, transcript, email, screenshot OCR text, or suspicious request here.",
        key="analysis_input",
    )

    col1, col2, col3, col4 = st.columns([1, 1, 1, 1])
    with col1:
        run_analysis = st.button("Run Analysis", use_container_width=True)
    with col2:
        clear_input = st.button("Clear Input", use_container_width=True)
    with col3:
        use_local_only = st.checkbox("Local only", value=False, help="Skip API calls and use the offline engine only.")
    with col4:
        save_to_history = st.checkbox("Save to history", value=True)

    if clear_input:
        st.session_state["analysis_input"] = ""
        st.session_state["uploaded_text"] = ""
        st.rerun()

    if not run_analysis and st.session_state.get("last_result") is not None and not user_text.strip():
        result: AnalysisResult = st.session_state["last_result"]
    elif run_analysis and user_text.strip():
        with st.spinner("Scanning content for manipulation patterns..."):
            result = analyze_text_local(
                user_text,
                source_type=st.session_state.get("uploaded_source_type", source_type),
                analyst_notes=analyst_notes,
            )
            ai_prompt = ""
            gemini_text = None
            hf_raw = None
            if not use_local_only:
                ai_prompt, gemini_text, hf_raw = enhance_with_ai(result)
            result.analyst_summary = result.analyst_summary if not gemini_text else gemini_text.strip()
            st.session_state["last_ai_prompt"] = ai_prompt
            st.session_state["last_gemini_text"] = gemini_text
            st.session_state["last_hf_text"] = summarize_hf_response(hf_raw)
            st.session_state["last_result"] = result
            if save_to_history:
                save_record(result)
        st.success("Analysis complete.")
    elif run_analysis and not user_text.strip():
        st.warning("Paste text or upload a file first.")
        return
    else:
        result = st.session_state.get("last_result")

    if result:
        render_status_bar(result)
        render_metric_grid(result)
        st.write("")
        left, right = st.columns([1.1, 0.9], gap="large")
        with left:
            st.markdown(
                f"""
                <div class="glass-card">
                    <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;">
                        <div>
                            <div style="font-size:1.15rem;font-weight:800;">{icon_for_level(result.threat_level)} {result.threat_level} Threat Assessment</div>
                            <div class="small-muted">Source: {html.escape(source_label(result.source_type))}</div>
                        </div>
                        <div>
                            <span class="{level_to_badge(result.threat_level)}">{html.escape(result.threat_level)}</span>
                        </div>
                    </div>
                    <div style="margin-top:0.8rem" class="report-box">
                        <strong>Verdict:</strong> {html.escape(result.verdict)}
                    </div>
                    <div style="margin-top:0.7rem" class="small-muted">{html.escape(result.uncertainty_note)}</div>
                    <div style="margin-top:0.7rem" class="small-muted">
                        <strong>What the attacker wants:</strong> {html.escape(result.what_attacker_wants)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            st.write("")
            if result.cleaned_text:
                st.markdown("##### Highlighted suspicious content")
                st.markdown(
                    f"""
                    <div class="glass-card" style="line-height:1.65;">
                        {highlight_text(result.cleaned_text[:4000], result.suspicious_phrases)}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        with right:
            st.plotly_chart(build_gauge(result.confidence, "Confidence", theme_tokens()["primary_2"]), use_container_width=True)
            st.plotly_chart(build_radar(result.tactic_counts), use_container_width=True)

        tab1, tab2, tab3, tab4 = st.tabs(["AI Insights", "Defense Playbook", "Raw Findings", "Export"])
        with tab1:
            st.markdown("##### AI Insights")
            st.write(result.analyst_summary)
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Detected tactics**")
                if result.tactic_counts:
                    for tactic, count in sorted(result.tactic_counts.items(), key=lambda x: (-x[1], x[0])):
                        st.markdown(f"<span class='analysis-chip'>{tactic.replace('_', ' ').title()} × {count}</span>", unsafe_allow_html=True)
                else:
                    st.info("No strong manipulation tactics were detected.")
                st.markdown("**Attack stage**")
                st.write(result.attack_stage)
                st.markdown("**Psychological trigger profile**")
                st.write(", ".join([t.replace("_", " ") for t in result.tactic_counts.keys()]) or "Neutral / low-pressure communication")
            with c2:
                st.markdown("**Likelihood indicators**")
                st.write(f"Manipulation: {result.manipulation_likelihood}/100")
                st.write(f"Exposure: {result.exposure_level}/100")
                st.write(f"Anomaly: {result.anomaly_level}/100")
                st.markdown("**Confidence note**")
                st.write(result.uncertainty_note)
                st.markdown("**Safe indicators**")
                st.write(", ".join(result.safe_indicators) if result.safe_indicators else "None observed")

        with tab2:
            st.markdown("##### Defense Playbook")
            st.markdown(f"**Recommended action now:** {result.recommendation_now}")
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("**Do not do this**")
                for item in result.do_not_do:
                    st.write(f"• {item}")
            with c2:
                st.markdown("**Safe verification steps**")
                for item in result.safe_verification_steps:
                    st.write(f"• {item}")
            with c3:
                st.markdown("**Report this to**")
                for item in result.report_to:
                    st.write(f"• {item}")

            st.markdown("**Quick safety messages**")
            safety_templates = [
                "I will verify through official channels.",
                "I will not click the link.",
                "Please contact me through the official number.",
            ]
            cols = st.columns(len(safety_templates))
            for col, tpl in zip(cols, safety_templates):
                with col:
                    st.code(tpl, language="text")

            if result.threat_level in {"High", "Critical"}:
                st.error("Escalation recommended: this content should be treated as potentially harmful until independently verified.")
            elif result.threat_level == "Moderate":
                st.warning("Proceed with caution and verify every claim before taking action.")
            else:
                st.success("No urgent response needed, but stay alert for hidden context.")

        with tab3:
            st.markdown("##### Raw Findings")
            st.write("Rationale:")
            for item in result.rationale or ["No strong indicators were found."]:
                st.write(f"• {item}")
            st.write("Suspicious phrases:", safe_join_phrases(result.suspicious_phrases))
            st.write("Safe indicators:", safe_join_phrases(result.safe_indicators))
            with st.expander("Structured JSON", expanded=False):
                st.code(json.dumps(asdict(result), indent=2, ensure_ascii=False), language="json")

            if st.session_state.get("last_gemini_text"):
                st.markdown("**Gemini enrichment**")
                st.write(st.session_state.get("last_gemini_text"))
            if st.session_state.get("last_hf_text"):
                st.markdown("**Hugging Face enrichment**")
                st.write(st.session_state.get("last_hf_text"))

        with tab4:
            st.markdown("##### Export and report")
            report_text = build_report_text(result, st.session_state.get("last_gemini_text", ""), st.session_state.get("last_hf_text", ""))
            json_blob = json.dumps(asdict(result), indent=2, ensure_ascii=False)
            csv_buffer = io.StringIO()
            writer = csv.writer(csv_buffer)
            writer.writerow(["field", "value"])
            writer.writerow(["created_at", result.created_at])
            writer.writerow(["risk_score", result.risk_score])
            writer.writerow(["threat_level", result.threat_level])
            writer.writerow(["confidence", result.confidence])
            writer.writerow(["tactic_summary", json.dumps(result.tactic_counts, ensure_ascii=False)])

            st.download_button("Download TXT report", report_text.encode("utf-8"), file_name="cognishield_report.txt", mime="text/plain")
            st.download_button("Download JSON", json_blob.encode("utf-8"), file_name="cognishield_analysis.json", mime="application/json")
            st.download_button("Download CSV summary", csv_buffer.getvalue().encode("utf-8"), file_name="cognishield_summary.csv", mime="text/csv")

            pdf_bytes = create_pdf_report(result, report_text)
            if pdf_bytes:
                st.download_button("Download PDF report", pdf_bytes, file_name="cognishield_report.pdf", mime="application/pdf")
            else:
                st.info("PDF export is unavailable in this environment. TXT / JSON / CSV exports are ready.")

            st.text_area("Copy-ready report text", report_text, height=260)

    else:
        st.info("Run an analysis to unlock the intelligence panels and report exports.")


def render_history_tab() -> None:
    st.subheader("History")
    st.caption("Search past analyses, review trends, and manage incident records.")
    top = st.columns([1, 1, 1, 1])
    with top[0]:
        risk_filter = st.selectbox("Risk level", ["All", "Low", "Moderate", "High", "Critical"])
    with top[1]:
        tactic_filter = st.selectbox(
            "Tactic filter",
            ["All"]
            + sorted([k.replace("_", " ").title() for k in TACTIC_LIBRARY.keys()]),
        )
    with top[2]:
        source_filter = st.selectbox("Source type", ["All", "text", "pdf", "docx", "image", "audio"])
    with top[3]:
        search_query = st.text_input("Search history", placeholder="Search text, notes, or results")

    df = load_history(risk_level=risk_filter, tactic_filter=(tactic_filter if tactic_filter != "All" else "All"), source_type=source_filter, query=search_query)
    if df.empty:
        st.info("No history found yet.")
        return

    st.write(f"Stored incidents: **{len(df)}**")
    c1, c2 = st.columns([1.1, 0.9], gap="large")
    with c1:
        line_fig, bar_fig = build_history_trends(df)
        if line_fig:
            st.plotly_chart(line_fig, use_container_width=True)
        if bar_fig:
            st.plotly_chart(bar_fig, use_container_width=True)
    with c2:
        heatmap = build_heatmap(df)
        if heatmap:
            st.plotly_chart(heatmap, use_container_width=True)
        level_counts = df["threat_level"].value_counts().reindex(["Low", "Moderate", "High", "Critical"]).fillna(0)
        st.markdown("**Threat distribution**")
        st.write(level_counts.to_dict())

    for _, row in df.head(20).iterrows():
        result_json = json.loads(row["result_json"])
        row_result = AnalysisResult(**result_json)
        with st.expander(f"{row_result.created_at} — {row_result.threat_level} ({row_result.risk_score}/100)", expanded=False):
            st.write(row_result.verdict)
            st.write(row_result.analyst_summary)
            st.write("Tactics:", ", ".join([k.replace("_", " ") for k in row_result.tactic_counts.keys()]) or "None")
            st.write("Notes:", row_result.analyst_notes or "—")
            left, right = st.columns([1, 1])
            with left:
                st.download_button(
                    "Download this record JSON",
                    json.dumps(result_json, indent=2, ensure_ascii=False).encode("utf-8"),
                    file_name=f"cognishield_{row_result.created_at.replace(':', '-')}.json",
                    mime="application/json",
                    key=f"json_{row['id']}",
                )
            with right:
                if st.button("Delete this record", key=f"del_{row['id']}"):
                    delete_history_row(int(row["id"]))
                    st.success("Record deleted.")
                    st.rerun()

    st.write("")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Clear All History", type="primary"):
            clear_history()
            st.success("All history cleared.")
            st.rerun()
    with c2:
        st.download_button(
            "Export filtered history CSV",
            df.to_csv(index=False).encode("utf-8"),
            file_name="cognishield_history.csv",
            mime="text/csv",
        )


def render_settings_tab() -> None:
    st.subheader("Settings")
    st.caption("Tune the engine, switch themes, and connect optional AI providers.")
    col1, col2 = st.columns([1, 1])

    with col1:
        st.session_state["dark_mode"] = st.toggle("Dark mode", value=st.session_state.get("dark_mode", False))
        st.session_state["analysis_verbosity"] = st.selectbox("Analysis verbosity", ["Compact", "Balanced", "Deep"], index=["Compact", "Balanced", "Deep"].index(st.session_state.get("analysis_verbosity", "Balanced")))
        st.session_state["sensitivity"] = st.slider("Sensitivity threshold", 1, 100, int(st.session_state.get("sensitivity", 55)))
        st.session_state["gemini_model"] = st.text_input("Gemini model name", value=st.session_state.get("gemini_model", "gemini-1.5-flash"))
        st.session_state["hf_model"] = st.text_input("Hugging Face model name", value=st.session_state.get("hf_model", "distilbert-base-uncased-finetuned-sst-2-english"))

    with col2:
        st.session_state["gemini_api_key"] = st.text_input("Gemini API key", value=st.session_state.get("gemini_api_key", os.getenv("GEMINI_API_KEY", "")), type="password")
        st.session_state["hf_api_key"] = st.text_input("Hugging Face API key", value=st.session_state.get("hf_api_key", os.getenv("HF_API_KEY", "")), type="password")
        st.session_state["admin_mode"] = st.toggle("Admin mode", value=st.session_state.get("admin_mode", False))
        st.caption("Keys are stored in session state only for this run. Prefer environment variables for deployment.")
        st.write(f"Database path: `{DB_PATH}`")

    st.markdown("##### Engine status")
    connection_status_badge("Local engine", True, "Always available")
    connection_status_badge("Gemini", bool(st.session_state.get("gemini_api_key") or os.getenv("GEMINI_API_KEY")), "Key detected" if (st.session_state.get("gemini_api_key") or os.getenv("GEMINI_API_KEY")) else "No key")
    connection_status_badge("Hugging Face", bool(st.session_state.get("hf_api_key") or os.getenv("HF_API_KEY")), "Key detected" if (st.session_state.get("hf_api_key") or os.getenv("HF_API_KEY")) else "No key")

    test_col1, test_col2 = st.columns(2)
    with test_col1:
        if st.button("Test Gemini Connection"):
            key = st.session_state.get("gemini_api_key", os.getenv("GEMINI_API_KEY", "")).strip()
            if not key:
                st.warning("No Gemini key configured.")
            else:
                with st.spinner("Testing Gemini..."):
                    sample = call_gemini_api(key, st.session_state.get("gemini_model", "gemini-1.5-flash"), "Reply with exactly: OK")
                st.success("Gemini responded." if sample else "Gemini call failed or returned no text.")
    with test_col2:
        if st.button("Test Hugging Face Connection"):
            key = st.session_state.get("hf_api_key", os.getenv("HF_API_KEY", "")).strip()
            if not key:
                st.warning("No Hugging Face key configured.")
            else:
                with st.spinner("Testing Hugging Face..."):
                    sample = call_huggingface_api(key, st.session_state.get("hf_model", "distilbert-base-uncased-finetuned-sst-2-english"), "This is a test message.")
                st.success("Hugging Face responded." if sample is not None else "Hugging Face call failed.")
    st.markdown("##### Maintenance")
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Reset session settings"):
            for key in ["dark_mode", "api_provider", "gemini_model", "hf_model", "analysis_verbosity", "sensitivity", "admin_mode", "last_result", "history_cache"]:
                if key in st.session_state:
                    del st.session_state[key]
            st.success("Session settings reset.")
            st.rerun()
    with col_b:
        if st.button("Clear stored history"):
            clear_history()
            st.success("History cleared.")
            st.rerun()


def render_about_tab() -> None:
    st.subheader("About")
    st.markdown(
        """
        CogniShield AI is a portfolio-ready cybersecurity intelligence dashboard for spotting scam patterns,
        manipulation tactics, impersonation attempts, and unsafe requests across text, screenshots, transcripts, and files.

        It uses a hybrid engine:
        - local lexical and contextual detection
        - weighted risk scoring
        - optional Gemini enrichment
        - optional Hugging Face inference
        - SQLite-backed history and analytics
        - polished reporting and export tools

        **Submitted By: Ravikant Arya**
        """
    )
    st.markdown(
        """
        **Tech stack:** Python, Streamlit, Plotly, Pandas, NumPy, Requests, SQLite, optional OCR / PDF / DOCX / audio tooling.

        **Design goal:** make the app feel like a premium cyber intelligence product rather than a classroom demo.
        """
    )
    st.info("For deployment, keep optional secrets in environment variables and install only the dependencies you actually need.")


def render_sidebar() -> None:
    st.sidebar.markdown(f"## {APP_NAME}")
    st.sidebar.markdown("Psychological threat intelligence for safer digital communication.")
    st.sidebar.markdown("<div class='sidebar-note'>Detect phishing, impersonation, fake support, OTP theft, scam links, and suspicious psychological pressure.</div>", unsafe_allow_html=True)

    st.sidebar.divider()
    st.sidebar.markdown("### Navigation")
    nav = st.sidebar.radio(
        "Go to",
        ["Overview", "Message Analyzer", "Threat Radar", "AI Insights", "Defense Playbook", "History", "Settings", "About"],
        index=["Overview", "Message Analyzer", "Threat Radar", "AI Insights", "Defense Playbook", "History", "Settings", "About"].index(st.session_state.get("active_tab", "Overview")),
        label_visibility="collapsed",
    )
    st.session_state["active_tab"] = nav

    st.sidebar.divider()
    st.sidebar.markdown("### Quick actions")
    if st.sidebar.button("Load OTP scam demo"):
        st.session_state["analysis_input"] = sample_cases()["Urgent OTP Scam"]
        st.session_state["active_tab"] = "Message Analyzer"
    if st.sidebar.button("Load safe message demo"):
        st.session_state["analysis_input"] = sample_cases()["Safe Message"]
        st.session_state["active_tab"] = "Message Analyzer"

    st.sidebar.divider()
    st.sidebar.markdown("### Engine status")
    connection_status_badge("Local Engine", True, "Online")
    connection_status_badge("Gemini", bool(st.session_state.get("gemini_api_key") or os.getenv("GEMINI_API_KEY")), "Available" if (st.session_state.get("gemini_api_key") or os.getenv("GEMINI_API_KEY")) else "Missing key")
    connection_status_badge("Hugging Face", bool(st.session_state.get("hf_api_key") or os.getenv("HF_API_KEY")), "Available" if (st.session_state.get("hf_api_key") or os.getenv("HF_API_KEY")) else "Missing key")

    st.sidebar.divider()
    st.sidebar.markdown("### At a glance")
    st.sidebar.metric("Sensitivity", st.session_state.get("sensitivity", 55))
    st.sidebar.metric("Verbosity", st.session_state.get("analysis_verbosity", "Balanced"))
    st.sidebar.metric("Theme", "Dark" if st.session_state.get("dark_mode") else "Light")


def render_threat_radar_tab() -> None:
    st.subheader("Threat Radar")
    st.caption("Radar-style pattern view, distribution charts, and incident concentration trends.")
    result = st.session_state.get("last_result")
    if not result:
        st.info("Run a message analysis first to unlock the radar view.")
        return

    left, right = st.columns([1, 1], gap="large")
    with left:
        st.plotly_chart(build_gauge(result.risk_score, "Threat Severity", theme_tokens()["primary"]), use_container_width=True)
        st.plotly_chart(build_radar(result.tactic_counts), use_container_width=True)
    with right:
        st.markdown("##### Live indicator profile")
        for label, value in [
            ("Risk", result.risk_score),
            ("Confidence", result.confidence),
            ("Manipulation", result.manipulation_likelihood),
            ("Exposure", result.exposure_level),
            ("Anomaly", result.anomaly_level),
        ]:
            st.progress(min(1.0, value / 100.0), text=f"{label}: {value}/100")

        if result.suspicious_phrases:
            st.markdown("**Top suspicious phrases**")
            for phrase in result.suspicious_phrases[:6]:
                st.markdown(f"<span class='analysis-chip'>{html.escape(phrase)}</span>", unsafe_allow_html=True)
        else:
            st.success("No suspicious phrases were strongly detected.")

    df = load_history()
    if not df.empty:
        st.markdown("##### Historical trend snapshots")
        line_fig, bar_fig = build_history_trends(df)
        heatmap = build_heatmap(df)
        if line_fig:
            st.plotly_chart(line_fig, use_container_width=True)
        if bar_fig:
            st.plotly_chart(bar_fig, use_container_width=True)
        if heatmap:
            st.plotly_chart(heatmap, use_container_width=True)


def render_ai_insights_tab() -> None:
    st.subheader("AI Insights")
    st.caption("Structured explanation of the message, attacker goal, and behavioral triggers.")
    result = st.session_state.get("last_result")
    if not result:
        st.info("Analyze a message first to unlock the intelligence summary.")
        return

    left, right = st.columns([1.05, 0.95], gap="large")
    with left:
        st.markdown("##### Analyst verdict")
        st.markdown(
            f"""
            <div class="glass-card">
                <div style="font-size:1.2rem;font-weight:800;margin-bottom:0.45rem;">{icon_for_level(result.threat_level)} {result.threat_level}</div>
                <div class="small-muted">{html.escape(result.verdict)}</div>
                <div style="margin-top:0.8rem" class="report-box"><strong>Recommended action now:</strong> {html.escape(result.recommendation_now)}</div>
                <div style="margin-top:0.7rem" class="small-muted"><strong>Confidence:</strong> {result.confidence:.1f}%</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write("")
        st.markdown("##### Detected tactics and trigger profile")
        if result.tactic_counts:
            for tactic, count in sorted(result.tactic_counts.items(), key=lambda x: (-x[1], x[0])):
                st.markdown(f"<span class='analysis-chip'>{tactic.replace('_', ' ').title()} × {count}</span>", unsafe_allow_html=True)
        else:
            st.info("No strong tactics were found. The message currently reads as low risk.")

    with right:
        st.markdown("##### What the attacker wants")
        st.write(result.what_attacker_wants)
        st.markdown("##### Attack stage")
        st.write(result.attack_stage)
        st.markdown("##### Uncertainty note")
        st.write(result.uncertainty_note)
        st.markdown("##### Safe indicators")
        st.write(", ".join(result.safe_indicators) if result.safe_indicators else "None observed")

    st.markdown("##### Analyst-style summary")
    st.write(result.analyst_summary)
    if st.session_state.get("last_gemini_text"):
        st.markdown("##### Gemini enrichment")
        st.write(st.session_state.get("last_gemini_text"))
    if st.session_state.get("last_hf_text"):
        st.markdown("##### Hugging Face enrichment")
        st.write(st.session_state.get("last_hf_text"))


def render_playbook_tab() -> None:
    st.subheader("Defense Playbook")
    st.caption("Immediate actions, safe verification, and reporting guidance.")
    result = st.session_state.get("last_result")
    if not result:
        st.info("Analyze a message first to personalize the playbook.")
        return

    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("##### Immediate action")
        st.write(result.recommendation_now)
        st.markdown("##### Do not do this")
        for item in result.do_not_do:
            st.write(f"• {item}")
    with c2:
        st.markdown("##### Safe verification checklist")
        for item in result.safe_verification_steps:
            st.write(f"• {item}")
        st.markdown("##### Report this to")
        for item in result.report_to:
            st.write(f"• {item}")
    with c3:
        st.markdown("##### Response templates")
        for tpl in [
            "I will verify through official channels.",
            "I will not click the link.",
            "Please contact me through the official number.",
        ]:
            st.code(tpl, language="text")

    if result.threat_level in {"High", "Critical"}:
        st.error("Escalation recommended. Treat the message as unsafe until independently confirmed.")
    elif result.threat_level == "Moderate":
        st.warning("Verification recommended before any action.")
    else:
        st.success("Low-risk pattern detected. Stay alert, but no urgent escalation is needed.")


def main() -> None:
    st.set_page_config(
        page_title=APP_NAME,
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    init_db()
    set_defaults()
    apply_css()
    render_sidebar()

    active = st.session_state.get("active_tab", "Overview")

    if active == "Overview":
        render_overview(st.session_state.get("last_result"))
    elif active == "Message Analyzer":
        render_analysis_tab()
    elif active == "Threat Radar":
        render_threat_radar_tab()
    elif active == "AI Insights":
        render_ai_insights_tab()
    elif active == "Defense Playbook":
        render_playbook_tab()
    elif active == "History":
        render_history_tab()
    elif active == "Settings":
        render_settings_tab()
    else:
        render_about_tab()

    st.caption("CogniShield AI • Defensive use only • Built for safer communication analysis and incident review.")


if __name__ == "__main__":
    main()
