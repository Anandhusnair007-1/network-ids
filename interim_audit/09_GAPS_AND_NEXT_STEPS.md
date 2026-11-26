# 09 — Gaps and Next Steps

Prioritized gaps identified during the read-only audit, ordered by deadline and technical impact.

---

## Priority 1 — Critical Academic & Submission Deadlines

1. **Interim Report (`25CSA698A`) Missing — Due 29th November 2026 (3 Days Away)**
   - **Gap:** `reports/TECHNICAL_PROJECT_REPORT.md` and `reports/Network_IDS_Project_Report_Anandhu_S_Nair.pdf` are written as a final report for old course code `21CSA391A` and do not follow `/home/anandhu/Downloads/Interim Report Template - S3.docx`.
   - **Action:** Author and export a clean **<= 20-page Interim Report PDF** for `Case Study 25CSA698A` using `08_INTERIM_REPORT_DATA.md` mapped strictly to the template sections (`Abstract <= 250 words`, `Objectives`, `Scope ~1 page`, `Introduction 2–3 pages`, `Background`, `Related Works`, `Detailed Problem Statement`, `Methods/Algorithms`, `Expected Results`).
   - **Compliance Check:** Verify plagiarism similarity **<= 10%**, AI usage **<= 20%**, and include explicit AI-tool disclosure per `S3 MCA Case Study Guidelines document (1).pdf`. Also confirm the Final Report date (`24th January 2026` typo in guidelines vs `2027`) on LMS.

---

## Priority 2 — Broken Python Virtual Environment (`.venv`)

2. **Host Python 3.14.4 vs. `.venv` Python 3.12 Mismatch**
   - **Gap:** `.venv/bin/python3` symlinks to `/usr/bin/python3` (`Python 3.14.4`), while installed packages (`pandas 3.0.6`, `scikit-learn 1.9.1`, `shap 0.54.1`, `streamlit 1.66.0`, `pyarrow 26.0.0`, `pytest 9.1.1`) sit in `.venv/lib/python3.12/site-packages/`. Running `.venv/bin/python3` fails with `ModuleNotFoundError: No module named 'pandas'` and `No module named pip`.
   - **Action:** Install Python 3.12 via `uv python install 3.12` (or rebuild `.venv` against Python 3.12/3.14 and reinstall `requirements-dev.txt`), then run `make check` and `make dashboard` to re-verify all 8 test files and live UI rendering.

---

## Priority 3 — Documentation, Metrics & Codebase Consistency

3. **Report-to-Code Drift**
   - `TECHNICAL_PROJECT_REPORT.md` claims a **5-page** dashboard and **3-tier** severity (`HIGH/MEDIUM/INFO`), whereas `dashboard/app.py` now has **6 pages** (added `Alert history`) and `src/policy.py` defaults to `TieredSeverityPolicy` (`HIGH/MEDIUM/LOW/INFO`).
   - `README.md` (line 226) also still says "five pages" instead of six.
   - `TECHNICAL_PROJECT_REPORT.md` (§11.5) cites a pre-fix `99.56%` alert compression ratio, while `src/alert_grouper.py` (`summarize_groups`) was fixed to avoid counting ungrouped alerts as saved work (`README.md` reports `8%`–`95%`).
4. **Unreproduced / Divergent Latency Numbers & Missing Confusion Matrices**
   - Latency differs across three documents (`12.16 us` in `README.md`, `15.79 us` in `TECHNICAL_PROJECT_REPORT.md`, `~47,000 flows/s` in `docs/DEPLOYMENT.md`), and no benchmark script exists in `src/` or `tests/`.
   - `eval_results.json` omits the binary/multiclass confusion matrices and per-class test precision/recall/F1 table.
   - **Action:** Add a small timing + confusion-matrix export to `src/evaluate_hybrid.py` (or a dedicated `src/benchmark.py`) and re-run once `.venv` is restored.
5. **Minor Docstring / Security Doc Discrepancy**
   - `docs/SECURITY.md` states `InputValidator` does "NaN/inf rejection", whereas `src/validator.py` sanitizes `NaN`, `±Inf`, and non-numeric strings to `0.0` (verified in `tests/test_security_and_validation.py`). Update doc wording to match behavior ("sanitization").
6. **Makefile & CI Placement Gaps**
   - `README.md` and `docs/RUNBOOK.md` reference `make manifest`, `make keygen`, `make sign`, and `make drift-reference`, none of which exist in `Makefile`.
   - `Makefile`'s `lint` and `compileall` omit `api/`.
   - CI workflow sits in `Claude outputs/ci.yml` rather than `.github/workflows/ci.yml`. Clean up `Claude outputs/` before academic code review.

---

## Priority 4 — Research & Production Hardening (Before Final Demo)

7. **Stratified vs. Temporal Split Validation:** Current 60/20/20 stratified split mixes flows from the same attack capture day across train and test; consider noting this limitation clearly in Viva or running a capture-day holdout check.
8. **Git Working Tree Hygiene:** Branch `phase-d-release-hardening` has 16 modified tracked files and 22 untracked files/directories (`api/`, `docs/`, `Dockerfile`, etc.). Commit clean changes before final demo/submission.
9. **Production Runtime Testing:** If demonstrating the `api/` or Docker setup in final review, run `docker compose build` and `TestClient` / load verification; keep `IDS_API_KEYS` and `IDS_DASH_PASSWORD_SHA256` out of git.
