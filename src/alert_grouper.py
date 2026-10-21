"""
src/alert_grouper.py
====================
Groups individual flow-level predictions into consolidated alert batches.
Mitigates Security Operations Center (SOC) alert fatigue.

Grouping strategies
-------------------
1. Timestamp-Based (Temporal Sliding Window):
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

        # Group by (final_label, severity)
        for (label, sev), sub in df.groupby(["final_label", "severity"], sort=False):
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
                ))
                gid += 1

        return groups

    # ------------------------------------------------------------------
    def _window_group(self, df: pd.DataFrame) -> list[AlertGroup]:
        """
        Sliding-window grouper when a valid Timestamp column is available.
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
                for (label, sev), sub in window_df.groupby(["final_label", "severity"], sort=False):
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
                    ))
                    gid += 1
            current = end

        return out


def groups_to_dataframe(groups: list[AlertGroup]) -> pd.DataFrame:
    """Convert a list of AlertGroup objects to an analytical DataFrame."""
    if not groups:
        return pd.DataFrame(columns=[
            "group_id", "label", "severity", "count",
            "avg_confidence", "avg_anomaly_score", "window_start", "window_end",
        ])
    return pd.DataFrame([
        {
            "group_id":          g.group_id,
            "label":             g.label,
            "severity":          g.severity,
            "count":             g.count,
            "avg_confidence":    round(g.avg_confidence, 4),
            "avg_anomaly_score": round(g.avg_anomaly_score, 4),
            "window_start":      g.window_start,
            "window_end":        g.window_end,
        }
        for g in groups
    ])
