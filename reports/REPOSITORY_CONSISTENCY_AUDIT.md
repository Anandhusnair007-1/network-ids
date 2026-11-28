# Repository Consistency Audit

Date: 2026-11-28. Environment: `/home/anandhu/projects/.venv-network-ids-312` (Python 3.12.16). No model, threshold or ML source file was changed. Nothing was committed.

## Corrected (documentation and build files only)

| # | Item | Was | Now | File |
|---|---|---|---|---|
| 1 | Dashboard page count | "five pages" / "5-page" | six pages (Overview, Scan flows, Incidents, Investigate flow, Alert history, Detector health), matching `PAGES` in `dashboard/app.py` | `README.md`, `reports/TECHNICAL_PROJECT_REPORT.md` |
| 2 | Severity levels | HIGH/MEDIUM/INFO | HIGH/MEDIUM/LOW/INFO (`TieredSeverityPolicy`) | `reports/TECHNICAL_PROJECT_REPORT.md` |
| 3 | Validator wording | "NaN/inf rejection" | sanitisation of NaN/inf/non-numeric to 0.0; missing columns rejected | `docs/SECURITY.md` |
| 4 | Missing Makefile targets | `manifest`, `keygen`, `sign`, `drift-reference` documented but absent | added, plus `benchmark`; `all` now runs `manifest` before `evaluate`, as the README claims | `Makefile` |
| 5 | `api/` not linted or compiled | `lint`, `check` skipped `api/` | included | `Makefile` |
| 6 | Hybrid Baseline accuracy | 98.24% | 92.16% (`reports/benchmarks/benchmark_results.json`, tn 379,820 / fp 39,477 / fn 45 / tp 84,695). 98.24% did not match any reproducible output. | `README.md` |
| 7 | Latency figures (12.16 us, 15.79 us, 47,000 flows/s) | three conflicting, unreproducible | one measured set from `make benchmark`: 15.10 us/flow at 10,000 flows, 10.13 us/flow at 50,000 | `README.md`, `reports/TECHNICAL_PROJECT_REPORT.md` (total row), `docs/DEPLOYMENT.md` |
| 8 | Alert compression 99.56% | pre-fix figure | marked non-reproducible; 8%-95% traffic-dependent range; RQ4 downgraded to "partially confirmed" | `reports/TECHNICAL_PROJECT_REPORT.md` |

Already fixed before this audit: CI workflow is at `.github/workflows/ci.yml`; `Claude outputs/` no longer exists.

## Verification

- `pytest tests -q`: 89 passed after the edits.
- `make -n manifest drift-reference keygen sign benchmark check`: all targets resolve.
- `make benchmark` equivalent (`run_benchmarks.py`) reproduced the published numbers: RF-only precision 0.9875 / recall 0.99941 / FPR 0.002557; Tiered precision 0.863039 / FPR 0.032054; Baseline precision 0.682078 / FPR 0.09415; withheld 94 / 123 / 217 detected.
- Of the new Makefile targets, `manifest` and `benchmark` were verified by running them; `keygen`, `sign` and `drift-reference` were dry-run at the time of this audit and executed afterwards (`models/drift_reference.json` regenerated and committed; keys and `models/manifest.json.sig` created locally and not tracked).

## Open items (not changed)

1. Resolved: `reports/TECHNICAL_PROJECT_REPORT.md` section 11.4 per-stage rows now use the measured 10,000-flow medians from `reports/benchmarks/benchmark_results.json` (scaler 1.20 ms, RF 78.62 ms, IF 66.84 ms; the 151.00 ms total also includes policy and overhead).
2. Resolved for the README: RF-only accuracy is now 99.78% (`rf_only.accuracy` 0.997774). Section 11.1 of the report is the multiclass table and was not changed; the measured multiclass test accuracy is 99.77% (0.997701).
3. Resolved: `.venv` was rebuilt with Python 3.12.16 from `requirements-dev.txt`; `make` targets use it without `PYTHON=`.
4. Benchmark peak RSS (2,113 MB) includes loading the full test split; it is not a serving-memory figure.
5. Single-flow latency is 76.8 ms per call (200-tree ensembles), so per-flow API use should batch.
6. Docker image not built or run locally (no Docker daemon; rootless Docker also failed with `operation not permitted`). API load was measured on one uvicorn worker and added as section 11.6 of the technical report; SQLite write load and the CSV endpoint were not load tested.
7. Git: `models/manifest.json.sig` is deliberately untracked; it only verifies against the local `keys/manifest_public.pem`.
8. Stratified random split shares capture days across train and test; metrics may be optimistic.
