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
4. Resolved: README now labels the 2,113 MB benchmark RSS as not a serving figure and adds the measured serving RSS (about 624 MB, one uvicorn worker after the load test).
5. Documented, no code change: single-flow latency is 76.8 ms per call (200-tree ensembles). README, `docs/DEPLOYMENT.md` and report section 11.6 say to batch.
6. Resolved for the image: `docker build` succeeds and the hardened API and dashboard containers run and pass health checks (details in `docs/DEPLOYMENT.md`). Still open: `docker compose up` and the `ingest` profile were not run, SQLite write load and the CSV endpoint were not load tested, and GitHub Actions has never run because the account is locked for billing.
7. By design: `models/manifest.json.sig` is deliberately untracked; it only verifies against the local `keys/manifest_public.pem`.
8. Documented, not fixable without retraining: the stratified random split shares capture days across train, validation and test. The limitation is now stated in the README and report section 9.3; a day-based split needs retraining, which is out of scope.
