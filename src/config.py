"""
src/config.py
=============
Centralized configuration management for the Network Intrusion Detection Platform.
Supports environment-variable overrides with safe, deterministic local fallbacks.
"""

from __future__ import annotations

import os
from pathlib import Path

# Base project root (resolved to absolute path)
_DEFAULT_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = Path(os.getenv("IDS_PROJECT_ROOT", str(_DEFAULT_ROOT))).resolve()

# Directory configuration
DATA_DIR = Path(os.getenv("IDS_DATA_DIR", str(PROJECT_ROOT / "data" / "processed"))).resolve()
RAW_DATA_DIR = Path(os.getenv("IDS_RAW_DATA_DIR", str(PROJECT_ROOT / "data" / "raw" / "MachineLearningCVE"))).resolve()
MODELS_DIR = Path(os.getenv("IDS_MODELS_DIR", str(PROJECT_ROOT / "models"))).resolve()
REPORTS_DIR = Path(os.getenv("IDS_REPORTS_DIR", str(PROJECT_ROOT / "reports"))).resolve()

# Security & Artifact Integrity
MANIFEST_PATH = Path(os.getenv("IDS_MANIFEST_PATH", str(MODELS_DIR / "manifest.json"))).resolve()
VERIFY_INTEGRITY = os.getenv("IDS_VERIFY_INTEGRITY", "true").strip().lower() in ("1", "true", "yes", "on")

# Operational Limits & Guardrails
MAX_UPLOAD_ROWS = int(os.getenv("IDS_MAX_UPLOAD_ROWS", "50000"))
MAX_UPLOAD_BYTES = int(os.getenv("IDS_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))  # 50 MB

# Algorithm & Decision Constants
ANOMALY_LABEL = "Anomaly (Unclassified)"
DEFAULT_CONTAMINATION = 0.05
DEFAULT_RANDOM_STATE = 42
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_MIN_ALERTS = 5

# Canonical Label Constants
BENIGN_LABEL = "BENIGN"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_INFO = "INFO"


# Columns that identify a flow endpoint. Training drops them (anti-shortcut-learning),
# but uploaded telemetry may carry them and the triage layer uses them to group incidents.
SRC_IP_ALIASES = ("Source IP", "Src IP", "src_ip")
DST_IP_ALIASES = ("Destination IP", "Dst IP", "dst_ip")
TIMESTAMP_COLUMN = "Timestamp"

# Raw CIC-IDS2017 CSVs encode the en-dash in "Web Attack – Brute Force" as byte 0x96 (cp1252).
# Read as UTF-8 it becomes U+FFFD, which is what the stored label_map / parquet files contain.
_MOJIBAKE = ("\ufffd", "\x96")


def pretty_label(label: str) -> str:
    """Return a display-safe class label (repairs the CIC-IDS2017 en-dash mojibake)."""
    text = str(label)
    for bad in _MOJIBAKE:
        text = text.replace(bad, "-")
    return text.replace(" - ", " \u2013 ") if text.startswith("Web Attack") else text


# ---------------------------------------------------------------------------
# Production services (API, incident store, alert export, ingestion)
# ---------------------------------------------------------------------------
def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


VAR_DIR = Path(os.getenv("IDS_VAR_DIR", str(PROJECT_ROOT / "var"))).resolve()   # DB, audit log, ingest folders
DB_PATH = Path(os.getenv("IDS_DB_PATH", str(VAR_DIR / "ids.sqlite3"))).resolve()
AUDIT_LOG_PATH = Path(os.getenv("IDS_AUDIT_LOG", str(VAR_DIR / "audit.log"))).resolve()

DEFAULT_POLICY = os.getenv("IDS_POLICY", "tiered")

# API: secure by default. No keys configured and anonymous access not explicitly allowed => refuse to start.
API_KEYS = tuple(k.strip() for k in os.getenv("IDS_API_KEYS", "").split(",") if k.strip())
API_ALLOW_ANON = _env_bool("IDS_API_ALLOW_ANON", False)
API_RATE_LIMIT_PER_MIN = int(os.getenv("IDS_RATE_LIMIT_PER_MIN", "120"))
API_METRICS_PUBLIC = _env_bool("IDS_METRICS_PUBLIC", False)

# Alert export (all optional; operator-controlled, never taken from request data)
WEBHOOK_URL = os.getenv("IDS_WEBHOOK_URL", "").strip()
WEBHOOK_SECRET = os.getenv("IDS_WEBHOOK_SECRET", "")
SYSLOG_ADDR = os.getenv("IDS_SYSLOG_ADDR", "").strip()          # host:port (UDP)
SINK_MIN_SEVERITY = os.getenv("IDS_SINK_MIN_SEVERITY", "MEDIUM").strip().upper()

# Supply chain: when set, models/manifest.json must carry a valid Ed25519 signature (manifest.json.sig)
MANIFEST_PUBKEY = os.getenv("IDS_MANIFEST_PUBKEY", "").strip()

# Dashboard login (set either; the hash form keeps the password out of the environment)
DASH_PASSWORD = os.getenv("IDS_DASH_PASSWORD", "")
DASH_PASSWORD_SHA256 = os.getenv("IDS_DASH_PASSWORD_SHA256", "").strip().lower()

DRIFT_REFERENCE_PATH = Path(os.getenv("IDS_DRIFT_REFERENCE", str(MODELS_DIR / "drift_reference.json"))).resolve()
