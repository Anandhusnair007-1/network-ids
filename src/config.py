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
