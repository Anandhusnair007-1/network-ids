"""
src/alert_grouper.py
====================
Groups individual flow-level predictions into consolidated alert batches.
Mitigates Security Operations Center (SOC) alert fatigue.

Grouping strategies
-------------------
1. Timestamp-Based (Temporal Tumbling Window):
   - When a valid 'Timestamp' column is present, groups alerts by label + severity
     within a sliding time window (default: 60 seconds).
2. Deterministic Bounded-Sequential (Index-Based):
   - When timestamps are absent or unparseable, groups consecutive or closely
     clustered flows of the same label + severity.
   - Prevents unrelated alerts separated by large index gaps from being globally merged.
   - A new group is initiated if the gap between consecutive alerts exceeds `max_index_gap`
     or if the group size reaches `max_group_size`.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

try:
    from config import DST_IP_ALIASES, SRC_IP_ALIASES
except ImportError:  # imported as part of the ``src`` package
    from src.config import DST_IP_ALIASES, SRC_IP_ALIASES

MIN_ALERTS = 5        # Minimum flows to emit an alert group
WINDOW_SIZE = 60      # Seconds for timestamp sliding window
MAX_INDEX_GAP = 50    # Maximum index gap between flows in the same sequential group
MAX_GROUP_SIZE = 1000 # Maximum flows per alert group


@dataclass
class AlertGroup:
    group_id:          int
    label:             str
    severity:          str
    count:             int
    avg_confidence:    float
    avg_anomaly_score: float
    window_start:      object   # int index or pd.Timestamp
    window_end:        object
    src_ip:            str | None = None   # only when the input carried a source-IP column
    dst_ip:            str | None = None


class AlertGrouper:
    """
    Consolidates individual flow-level alerts into incident groups.

    Parameters
    ----------
    min_alerts : int
        Minimum number of flows required to form an alert group.
    window_size : int
        Sliding window duration in seconds (used when Timestamp is present).
    max_index_gap : int
        Maximum index gap between consecutive alerts of the same type before
        partitioning into a new group (used when Timestamp is absent).
    max_group_size : int
        Maximum flows allowable per group before closing.
    include_benign : bool
        Whether to group normal BENIGN/INFO traffic. Defaults to False (only group alerts).
    """

    def __init__(
        self,
        min_alerts: int = MIN_ALERTS,
        window_size: int = WINDOW_SIZE,
        max_index_gap: int = MAX_INDEX_GAP,
        max_group_size: int = MAX_GROUP_SIZE,
        include_benign: bool = False,
    ) -> None:
        self.min_alerts     = min_alerts
        self.window_size    = window_size
        self.max_index_gap  = max_index_gap
        self.max_group_size = max_group_size
        self.include_benign = include_benign

    @staticmethod
    def _entity_columns(df: pd.DataFrame) -> tuple[str | None, str | None]:
        """Detect source/destination IP columns (CIC-IDS2017 headers or common aliases)."""
        src = next((c for c in SRC_IP_ALIASES if c in df.columns), None)
        dst = next((c for c in DST_IP_ALIASES if c in df.columns), None)
        return src, dst

    def _group_keys(self, df: pd.DataFrame) -> list[str]:
        src, dst = self._entity_columns(df)
        return ["final_label", "severity"] + [c for c in (src, dst) if c]

    @staticmethod
    def _split_key(df_cols_src_dst, key) -> tuple[str, str, str | None, str | None]:
        label, sev, *rest = key if isinstance(key, tuple) else (key,)
        src_col, dst_col = df_cols_src_dst
        it = iter(rest)
        src = str(next(it)) if src_col else None
        dst = str(next(it)) if dst_col else None
        return str(label), str(sev), src, dst

    def group(self, df: pd.DataFrame) -> list[AlertGroup]:
        """
        Group predictions DataFrame into alert groups.

        Parameters
        ----------
        df : pd.DataFrame
            Must contain columns: 'final_label', 'severity', 'rf_confidence', 'anomaly_score'.
            Optionally contains 'Timestamp'.

        Returns
        -------
        list[AlertGroup]
        """
        required = {"final_label", "severity", "rf_confidence", "anomaly_score"}
        missing  = required - set(df.columns)
        if missing:
            raise ValueError(f"Missing required columns in prediction DataFrame: {missing}")

        if df.empty:
            return []

        # Filter out benign traffic if include_benign is False
        if not self.include_benign:
            df = df[df["severity"] != "INFO"].copy()
            if df.empty:
                return []

        # Check for valid Timestamp column
        has_ts = False
        if "Timestamp" in df.columns:
            ts_series = pd.to_datetime(df["Timestamp"], errors="coerce")
            if ts_series.notna().any():
                has_ts = True
                df = df.copy()
                df["Timestamp"] = ts_series
                df = df.sort_values("Timestamp").reset_index(drop=True)

        if has_ts:
            return self._window_group(df)
        return self._sequential_index_group(df)

    # ------------------------------------------------------------------
    def _sequential_index_group(self, df: pd.DataFrame) -> list[AlertGroup]:
        """
        Deterministic bounded-sequential grouping when timestamps are absent.
        Groups temporally clustered alerts while partitioning across index gaps.
        """
        groups: list[AlertGroup] = []
        gid = 0

        # Group by (final_label, severity[, src_ip, dst_ip])
        entity = self._entity_columns(df)
        for key, sub in df.groupby(self._group_keys(df), sort=False):
            label, sev, src_ip, dst_ip = self._split_key(entity, key)
            if len(sub) < self.min_alerts:
                continue

            indices = sub.index.to_numpy()
            confs   = sub["rf_confidence"].to_numpy()
            scores  = sub["anomaly_score"].to_numpy()

            # Partition indices into clusters where gap <= max_index_gap
            cluster_start_idx = 0
            for i in range(1, len(indices)):
                gap = indices[i] - indices[i - 1]
                cluster_len = i - cluster_start_idx

                if gap > self.max_index_gap or cluster_len >= self.max_group_size:
                    # Emit current cluster if it meets min_alerts
                    if cluster_len >= self.min_alerts:
                        c_confs  = confs[cluster_start_idx:i]
                        c_scores = scores[cluster_start_idx:i]
                        groups.append(AlertGroup(
                            group_id=gid,
                            label=str(label),
                            severity=str(sev),
                            count=cluster_len,
                            avg_confidence=float(c_confs.mean()),
                            avg_anomaly_score=float(c_scores.mean()),
                            window_start=int(indices[cluster_start_idx]),
                            window_end=int(indices[i - 1]),
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                        ))
                        gid += 1
                    cluster_start_idx = i

            # Final trailing cluster
            final_cluster_len = len(indices) - cluster_start_idx
            if final_cluster_len >= self.min_alerts:
                c_confs  = confs[cluster_start_idx:]
                c_scores = scores[cluster_start_idx:]
                groups.append(AlertGroup(
                    group_id=gid,
                    label=str(label),
                    severity=str(sev),
                    count=final_cluster_len,
                    avg_confidence=float(c_confs.mean()),
                    avg_anomaly_score=float(c_scores.mean()),
                    window_start=int(indices[cluster_start_idx]),
                    window_end=int(indices[-1]),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                ))
                gid += 1

        return groups

    # ------------------------------------------------------------------
    def _window_group(self, df: pd.DataFrame) -> list[AlertGroup]:
        """
        Fixed-width (tumbling) window grouper when a valid Timestamp column is available.
        """
        out: list[AlertGroup] = []
        gid = 0
        valid_df = df[df["Timestamp"].notna()]
        if valid_df.empty:
            return out

        min_ts = valid_df["Timestamp"].min()
        max_ts = valid_df["Timestamp"].max()
        window = pd.Timedelta(seconds=self.window_size)
        current = min_ts

        while current <= max_ts:
            end = current + window
            mask = (valid_df["Timestamp"] >= current) & (valid_df["Timestamp"] < end)
            window_df = valid_df[mask]

            if not window_df.empty:
                entity = self._entity_columns(window_df)
                for key, sub in window_df.groupby(self._group_keys(window_df), sort=False):
                    label, sev, src_ip, dst_ip = self._split_key(entity, key)
                    if len(sub) < self.min_alerts:
                        continue
                    out.append(AlertGroup(
                        group_id=gid,
                        label=str(label),
                        severity=str(sev),
                        count=len(sub),
                        avg_confidence=float(sub["rf_confidence"].mean()),
                        avg_anomaly_score=float(sub["anomaly_score"].mean()),
                        window_start=current,
                        window_end=end,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                    ))
                    gid += 1
            current = end

        return out


def groups_to_dataframe(groups: list[AlertGroup]) -> pd.DataFrame:
    """Convert a list of AlertGroup objects to an analytical DataFrame."""
    base_cols = [
        "group_id", "label", "severity", "count",
        "avg_confidence", "avg_anomaly_score", "window_start", "window_end",
    ]
    if not groups:
        return pd.DataFrame(columns=base_cols)
    rows = []
    for g in groups:
        row = {
            "group_id":          g.group_id,
            "label":             g.label,
            "severity":          g.severity,
            "count":             g.count,
            "avg_confidence":    round(g.avg_confidence, 4),
            "avg_anomaly_score": round(g.avg_anomaly_score, 4),
            "window_start":      g.window_start,
            "window_end":        g.window_end,
        }
        if g.src_ip is not None or g.dst_ip is not None:
            row["src_ip"] = g.src_ip
            row["dst_ip"] = g.dst_ip
        rows.append(row)
    return pd.DataFrame(rows)


def summarize_groups(groups: list[AlertGroup], n_alerts: int) -> dict[str, float]:
    """
    Honest triage KPIs.

    ``n_alerts`` is the number of raw (non-INFO) alerts that were offered to the grouper.
    Alerts that did not reach ``min_alerts`` are *not* compressed - they stay individual
    alerts - so they are reported separately instead of being counted as saved work.
    """
    incidents = len(groups)
    covered = int(sum(g.count for g in groups))
    ungrouped = max(n_alerts - covered, 0)
    queue_after = incidents + ungrouped
    reduction = (1 - queue_after / n_alerts) if n_alerts else 0.0
    return {
        "raw_alerts": int(n_alerts),
        "incidents": incidents,
        "alerts_in_incidents": covered,
        "ungrouped_alerts": ungrouped,
        "analyst_queue": queue_after,
        "queue_reduction": float(reduction),
    }
