"""
src/store.py
============
Durable incident store (SQLite, standard library only).

Why SQLite: a single-node SOC console needs durability and queryability, not a database server.
WAL mode gives concurrent readers; every statement is parameterised (no string-built SQL).
Swap this module for Postgres when you need multiple writers across hosts.

Analyst verdicts are stored next to each alert. ``export_feedback`` turns them into a labelled
dataset, which is what closes the loop for retraining on your own network.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pandas as pd

STATUSES = ("new", "acknowledged", "confirmed", "false_positive")
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id   TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    source     TEXT NOT NULL,
    policy     TEXT NOT NULL,
    n_flows    INTEGER NOT NULL,
    n_alerts   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id      TEXT PRIMARY KEY,
    batch_id      TEXT NOT NULL REFERENCES batches(batch_id),
    created_at    REAL NOT NULL,
    flow_index    INTEGER NOT NULL,
    severity      TEXT NOT NULL,
    final_label   TEXT NOT NULL,
    rf_label      TEXT NOT NULL,
    rf_confidence REAL NOT NULL,
    anomaly_score REAL NOT NULL,
    src_ip        TEXT,
    dst_ip        TEXT,
    flow_ts       TEXT,
    true_label    TEXT,
    status        TEXT NOT NULL DEFAULT 'new',
    note          TEXT NOT NULL DEFAULT '',
    updated_at    REAL NOT NULL,
    features_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_sev_time ON alerts(severity, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
"""

_SRC = ("Source IP", "Src IP", "src_ip")
_DST = ("Destination IP", "Dst IP", "dst_ip")


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _first(df: pd.DataFrame, names: tuple[str, ...]) -> str | None:
    return next((c for c in names if c in df.columns), None)


class IncidentStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    def save_batch(
        self,
        results: pd.DataFrame,
        source: str,
        policy: str,
        feature_cols: list[str] | None = None,
        keep_features: bool = True,
    ) -> tuple[str, list[str]]:
        """Persist a scored batch. Only non-INFO flows become alert rows. Returns (batch_id, alert_ids)."""
        now = time.time()
        batch_id = uuid.uuid4().hex
        alerts = results[results["severity"] != "INFO"]
        src, dst = _first(results, _SRC), _first(results, _DST)
        rows, ids = [], []
        for idx, r in alerts.iterrows():
            aid = uuid.uuid4().hex
            ids.append(aid)
            feats = None
            if keep_features and feature_cols:
                feats = json.dumps({c: float(r[c]) for c in feature_cols if c in r.index})
            rows.append((
                aid, batch_id, now, _as_int(idx), str(r["severity"]),
                str(r["final_label"]), str(r["rf_label"]), float(r["rf_confidence"]), float(r["anomaly_score"]),
                str(r[src]) if src else None, str(r[dst]) if dst else None,
                str(r["Timestamp"]) if "Timestamp" in r.index else None,
                str(r["Label"]) if "Label" in r.index else None,
                now, feats,
            ))
        with self._lock:
            self._conn.execute(
                "INSERT INTO batches VALUES (?,?,?,?,?,?)",
                (batch_id, now, source[:200], policy, len(results), len(alerts)),
            )
            self._conn.executemany(
                "INSERT INTO alerts (alert_id,batch_id,created_at,flow_index,severity,final_label,rf_label,"
                "rf_confidence,anomaly_score,src_ip,dst_ip,flow_ts,true_label,updated_at,features_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            self._conn.commit()
        return batch_id, ids

    # ------------------------------------------------------------------
    def list_alerts(
        self,
        severity: list[str] | None = None,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        clauses, params = [], []
        if severity:
            clauses.append(f"severity IN ({','.join('?' * len(severity))})")
            params += [s.upper() for s in severity]
        if status:
            if status not in STATUSES:
                raise ValueError(f"status must be one of {STATUSES}")
            clauses.append("status = ?")
            params.append(status)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        # Only "?" placeholders are interpolated into the clause; every value is bound as a parameter.
        sql = (
            "SELECT alert_id,batch_id,created_at,severity,final_label,rf_label,rf_confidence,anomaly_score,"  # nosec B608
            "src_ip,dst_ip,flow_ts,true_label,status,note,updated_at FROM alerts "
            f"{where} ORDER BY CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 WHEN 'LOW' THEN 2 ELSE 3 END, "
            "created_at DESC LIMIT ? OFFSET ?"
        )
        with self._lock:
            cur = self._conn.execute(sql, [*params, limit, int(offset)])
            return [dict(r) for r in cur.fetchall()]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
        return dict(row) if row else None

    def set_status(self, alert_id: str, status: str, note: str = "") -> bool:
        if status not in STATUSES:
            raise ValueError(f"status must be one of {STATUSES}")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET status = ?, note = ?, updated_at = ? WHERE alert_id = ?",
                (status, note[:1000], time.time(), alert_id),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def stats(self) -> dict[str, Any]:
        with self._lock:
            sev = {r["severity"]: r["n"] for r in self._conn.execute(
                "SELECT severity, COUNT(*) n FROM alerts GROUP BY severity")}
            st = {r["status"]: r["n"] for r in self._conn.execute(
                "SELECT status, COUNT(*) n FROM alerts GROUP BY status")}
            b = self._conn.execute("SELECT COUNT(*) n, COALESCE(SUM(n_flows),0) f FROM batches").fetchone()
        return {"by_severity": sev, "by_status": st, "batches": b["n"], "flows_scanned": b["f"]}

    def export_feedback(self) -> pd.DataFrame:
        """
        Analyst-labelled alerts as a retraining dataset.

        ``confirmed`` -> attack (label = the verdict label), ``false_positive`` -> BENIGN.
        Rows without stored features are skipped.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT alert_id, final_label, status, features_json FROM alerts "
                "WHERE status IN ('confirmed','false_positive') AND features_json IS NOT NULL"
            ).fetchall()
        recs = []
        for r in rows:
            rec = json.loads(r["features_json"])
            rec["alert_id"] = r["alert_id"]
            rec["Label"] = "BENIGN" if r["status"] == "false_positive" else r["final_label"]
            recs.append(rec)
        return pd.DataFrame(recs)
