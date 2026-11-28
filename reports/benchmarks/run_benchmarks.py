#!/usr/bin/env python3
"""
Reproducible Phase 4 Evaluation & Inference Latency Benchmark.
Uses existing trained models and processed parquet splits without modifying models or thresholds.
Saves outputs under reports/benchmarks/.
"""

from __future__ import annotations

import json
import os
import platform
import resource
import sys
import time
import tracemalloc
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from config import DATA_DIR, MODELS_DIR, REPORTS_DIR, pretty_label  # noqa: E402
from hybrid import HybridDetector  # noqa: E402
from policy import POLICY_INFO, build_policy  # noqa: E402

BENCH_DIR = REPORTS_DIR / "benchmarks"
BENCH_DIR.mkdir(parents=True, exist_ok=True)


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _mem_total_gb() -> float:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                kb = int(line.split()[1])
                return round(kb / (1024 ** 2), 2)
    except OSError:
        pass
    return 0.0


def _binary_cm_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    prec = tp / max(tp + fp, 1)
    rec = tp / max(tp + fn, 1)
    f1 = (2 * prec * rec) / max(prec + rec, 1e-12) if (prec + rec) > 0 else 0.0
    fpr = fp / max(fp + tn, 1)
    acc = (tp + tn) / max(tp + tn + fp + fn, 1)
    return {
        "matrix_labels": ["BENIGN (0)", "ATTACK (1)"],
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
        "accuracy": round(acc, 6),
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1": round(f1, 6),
        "fpr": round(fpr, 6),
        "n_alerts": int(tp + fp),
    }


def main() -> None:
    # 1. Measure cold model load time separately from inference
    tracemalloc.start()
    t_load0 = time.perf_counter()
    det = HybridDetector.load(models_dir=MODELS_DIR, data_dir=DATA_DIR)
    load_seconds = time.perf_counter() - t_load0
    _, load_peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    feats: list[str] = json.loads((DATA_DIR / "features.json").read_text(encoding="utf-8"))
    test_df = pd.read_parquet(DATA_DIR / "test.parquet")
    withheld_df = pd.read_parquet(DATA_DIR / "withheld.parquet")

    X_test_raw = test_df[feats].to_numpy(dtype=np.float32)
    y_test_bin = test_df["is_attack"].to_numpy(dtype=np.int32)
    y_test_labels = test_df["Label"].map(pretty_label).to_numpy()

    X_w_raw = withheld_df[feats].to_numpy(dtype=np.float32)
    w_labels = withheld_df["Label"].map(pretty_label).to_numpy()

    # 2. Full evaluation on test.parquet (N=504,037) and withheld.parquet (N=2,179)
    X_test_scaled = det.scaler.transform(X_test_raw)
    sig_t = det.signals(X_test_scaled)
    X_w_scaled = det.scaler.transform(X_w_raw)
    sig_w = det.signals(X_w_scaled)

    # Multiclass RF evaluation on known test split
    rf_pred_labels = np.array([pretty_label(x) for x in sig_t["rf_labels"]], dtype=object)
    known_classes = sorted(set(y_test_labels.tolist()) | set(rf_pred_labels.tolist()))
    mc_cm = confusion_matrix(y_test_labels, rf_pred_labels, labels=known_classes)
    mc_report = classification_report(
        y_test_labels, rf_pred_labels, labels=known_classes, output_dict=True, zero_division=0
    )

    rf_bin_pred = (sig_t["rf_codes"] != det._benign_code).astype(np.int32)
    rf_binary_metrics = _binary_cm_metrics(y_test_bin, rf_bin_pred)

    # Policy evaluations (actionable = HIGH+MEDIUM, all_alerts = HIGH+MEDIUM+LOW)
    policy_metrics: dict[str, dict] = {}
    for key, info in POLICY_INFO.items():
        pol = build_policy(key, det.threshold)
        _, sev_t, _, _ = pol.evaluate(
            rf_codes=sig_t["rf_codes"],
            rf_confs=sig_t["rf_confs"],
            rf_labels=sig_t["rf_labels"],
            if_scores=sig_t["if_scores"],
            base_threshold=det.threshold,
            benign_code=det._benign_code,
        )
        _, sev_w, _, _ = pol.evaluate(
            rf_codes=sig_w["rf_codes"],
            rf_confs=sig_w["rf_confs"],
            rf_labels=sig_w["rf_labels"],
            if_scores=sig_w["if_scores"],
            base_threshold=det.threshold,
            benign_code=det._benign_code,
        )
        act_mask_t = np.isin(sev_t, ["HIGH", "MEDIUM"]).astype(np.int32)
        all_mask_t = (sev_t != "INFO").astype(np.int32)

        act_mask_w = np.isin(sev_w, ["HIGH", "MEDIUM"])
        all_mask_w = sev_w != "INFO"

        policy_metrics[key] = {
            "label": info["label"],
            "actionable": _binary_cm_metrics(y_test_bin, act_mask_t),
            "all_alerts": _binary_cm_metrics(y_test_bin, all_mask_t),
            "severity_counts_test": {s: int((sev_t == s).sum()) for s in ("HIGH", "MEDIUM", "LOW", "INFO")},
            "withheld": {
                "overall_actionable_rate": round(float(act_mask_w.mean()), 6),
                "overall_all_alerts_rate": round(float(all_mask_w.mean()), 6),
                "overall_actionable_count": int(act_mask_w.sum()),
                "overall_all_alerts_count": int(all_mask_w.sum()),
                "per_label": {
                    lbl: {
                        "total": int((w_labels == lbl).sum()),
                        "actionable_detected": int(act_mask_w[w_labels == lbl].sum()),
                        "actionable_rate": round(float(act_mask_w[w_labels == lbl].mean()), 6),
                        "all_alerts_detected": int(all_mask_w[w_labels == lbl].sum()),
                        "all_alerts_rate": round(float(all_mask_w[w_labels == lbl].mean()), 6),
                    }
                    for lbl in sorted(set(w_labels))
                },
            },
        }

    # Withheld RF vs IF raw counts
    rf_w_det = sig_w["rf_codes"] != det._benign_code
    if_w_det = sig_w["if_scores"] < det.threshold
    hyb_w_det = rf_w_det | if_w_det
    withheld_raw = {
        "total": int(len(w_labels)),
        "rf_detected": int(rf_w_det.sum()),
        "if_detected": int(if_w_det.sum()),
        "hybrid_baseline_detected": int(hyb_w_det.sum()),
        "per_label": {
            lbl: {
                "total": int((w_labels == lbl).sum()),
                "rf_detected": int(rf_w_det[w_labels == lbl].sum()),
                "if_detected": int(if_w_det[w_labels == lbl].sum()),
                "hybrid_baseline_detected": int(hyb_w_det[w_labels == lbl].sum()),
            }
            for lbl in sorted(set(w_labels))
        },
    }

    # 3. Reproducible Inference Latency & Memory Benchmark
    # Fixed random seed sampling from held-out test set
    rng = np.random.default_rng(42)
    batch_configs = [
        (1, 50, 200),       # (batch_size, warmup_iters, timed_iters)
        (100, 15, 50),
        (1000, 10, 30),
        (10000, 5, 20),
        (50000, 3, 10),
    ]
    # Use tiered (default) policy for full end-to-end inference timing
    det_tiered = det.with_policy(build_policy("tiered", det.threshold))

    latency_results: list[dict] = []
    for bs, n_warm, n_iter in batch_configs:
        idx = rng.integers(0, len(X_test_raw), size=bs)
        X_batch = np.ascontiguousarray(X_test_raw[idx], dtype=np.float32)

        # Warm-up iterations
        for _ in range(n_warm):
            _ = det_tiered._infer(det_tiered.scaler.transform(X_batch))

        total_ms, scaler_ms, rf_ms, if_ms = [], [], [], []
        tracemalloc.start()
        for _ in range(n_iter):
            t0 = time.perf_counter()
            Xs = det_tiered.scaler.transform(X_batch)
            t1 = time.perf_counter()
            _ = det_tiered.rf.predict_proba(Xs)
            t2 = time.perf_counter()
            _ = det_tiered.iforest.decision_function(Xs)
            t3 = time.perf_counter()
            t_e2e0 = time.perf_counter()
            # Full vectorized end-to-end call for accurate total latency
            _ = det_tiered._infer(det_tiered.scaler.transform(X_batch))
            t_end = time.perf_counter()

            scaler_ms.append((t1 - t0) * 1000.0)
            rf_ms.append((t2 - t1) * 1000.0)
            if_ms.append((t3 - t2) * 1000.0)
            total_ms.append((t_end - t_e2e0) * 1000.0)
        _, peak_b = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        arr_tot = np.array(total_ms)
        med_ms = float(np.median(arr_tot))
        p95_ms = float(np.percentile(arr_tot, 95))
        p99_ms = float(np.percentile(arr_tot, 99))
        us_per_flow_med = (med_ms * 1000.0) / bs
        throughput_med = (bs / (med_ms / 1000.0)) if med_ms > 0 else 0.0

        latency_results.append({
            "batch_size": bs,
            "warmup_iters": n_warm,
            "timed_iters": n_iter,
            "total_ms_median": round(med_ms, 4),
            "total_ms_p95": round(p95_ms, 4),
            "total_ms_p99": round(p99_ms, 4),
            "us_per_flow_median": round(us_per_flow_med, 3),
            "throughput_flows_per_sec_median": round(throughput_med, 1),
            "stage_median_ms": {
                "scaler": round(float(np.median(scaler_ms)), 4),
                "rf_predict_proba": round(float(np.median(rf_ms)), 4),
                "iforest_decision_function": round(float(np.median(if_ms)), 4),
            },
            "peak_traced_alloc_mb": round(peak_b / (1024 ** 2), 3),
        })

    ru_maxrss_mb = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)

    out = {
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu_model": _cpu_model(),
            "cpu_count": os.cpu_count(),
            "ram_total_gb": _mem_total_gb(),
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scikit_learn": sklearn.__version__,
            "random_seed": 42,
            "if_threshold": det.threshold,
        },
        "loading": {
            "cold_load_seconds": round(load_seconds, 4),
            "load_peak_traced_mb": round(load_peak_bytes / (1024 ** 2), 3),
        },
        "known_test_binary": {
            "n_rows": int(len(y_test_bin)),
            "rf_only": rf_binary_metrics,
            "policies": policy_metrics,
        },
        "known_test_multiclass_rf": {
            "n_rows": int(len(y_test_labels)),
            "classes": known_classes,
            "accuracy": round(float(accuracy_score(y_test_labels, rf_pred_labels)), 6),
            "macro_precision": round(float(precision_score(y_test_labels, rf_pred_labels, average="macro", zero_division=0)), 6),
            "macro_recall": round(float(recall_score(y_test_labels, rf_pred_labels, average="macro", zero_division=0)), 6),
            "macro_f1": round(float(f1_score(y_test_labels, rf_pred_labels, average="macro", zero_division=0)), 6),
            "weighted_f1": round(float(f1_score(y_test_labels, rf_pred_labels, average="weighted", zero_division=0)), 6),
            "per_class": {
                cls: {
                    "precision": round(float(mc_report[cls]["precision"]), 6),
                    "recall": round(float(mc_report[cls]["recall"]), 6),
                    "f1": round(float(mc_report[cls]["f1-score"]), 6),
                    "support": int(mc_report[cls]["support"]),
                }
                for cls in known_classes
            },
            "confusion_matrix": mc_cm.tolist(),
        },
        "withheld_experiment": withheld_raw,
        "latency_benchmark": {
            "policy": "tiered",
            "process_peak_rss_mb": ru_maxrss_mb,
            "batches": latency_results,
        },
    }

    out_json = BENCH_DIR / "benchmark_results.json"
    out_json.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_json}")
    print(f"Cold load: {load_seconds:.3f}s | Process peak RSS: {ru_maxrss_mb} MB")
    print("RF multiclass acc:", out["known_test_multiclass_rf"]["accuracy"], "macro_f1:", out["known_test_multiclass_rf"]["macro_f1"])
    for b in latency_results:
        print(f"  batch={b['batch_size']:>5}: med={b['total_ms_median']:>8.3f} ms ({b['us_per_flow_median']:>7.2f} us/flow, {b['throughput_flows_per_sec_median']:>10.1f} flows/s) p95={b['total_ms_p95']:>8.3f} ms")


if __name__ == "__main__":
    main()
