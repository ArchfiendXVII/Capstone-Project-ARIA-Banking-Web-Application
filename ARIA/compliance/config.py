from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "data"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
DEFAULT_DB_PATH = BASE_DIR / "aria_bank.db"

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4-turbo")
MAX_ITERATIONS = int(os.environ.get("COMPLIANCE_SCAN_MAX_ITERATIONS", "3"))
VERDICT_TTL_DAYS = int(os.environ.get("COMPLIANCE_VERDICT_TTL_DAYS", "7"))
APP_HOST = os.environ.get("COMPLIANCE_APP_HOST", "127.0.0.1")
APP_PORT = int(os.environ.get("COMPLIANCE_APP_PORT", "5000"))

REQUIRED_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

PRIVACY_ROUTES = [
    "/privacy",
    "/privacy/export",
    "/privacy/delete",
    "/privacy/consent",
]

KPI_BASELINES = {
    "KPI-01": {"baseline": 18, "target": 3},
    "KPI-02": {"baseline": 10, "target": 0},
    "KPI-03": {"baseline": 6, "target": 0},
    "KPI-04": {"baseline": 4, "target": 0},
    "KPI-05": {"baseline": 2, "target": 0},
    "KPI-06": {"baseline": 8, "target": 0},
    "KPI-07": {"baseline": 6, "target": 1},
    "KPI-08": {"baseline": 60, "target": 95},
    "KPI-09": {"baseline": 0, "target": 100},
    "KPI-10": {"baseline": 0, "target": 4},
    "KPI-11": {"baseline": 0, "target": 5},
    "KPI-12": {"baseline": 1, "target": 4},
    "KPI-13": {"baseline": None, "target": 7},
    "KPI-14": {"baseline": None, "target": 95},
    "KPI-15": {"baseline": 35, "target": 80},
}

COMPLIANCE_SCORE_BASELINES = {
    "owasp": 35.0,
    "iso": 40.0,
    "nist": 35.0,
    "gdpr": 30.0,
}
