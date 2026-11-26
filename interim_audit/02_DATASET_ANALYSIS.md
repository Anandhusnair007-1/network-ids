# 02 — Dataset Analysis

**Dataset:** CIC-IDS2017 (`MachineLearningCVE` CSV release)  
**Raw Location:** `/home/anandhu/projects/network-ids/data/raw/MachineLearningCVE/` (844 MB on disk, 8 CSV files)  
**Processed Location:** `/home/anandhu/projects/network-ids/data/processed/` (352 MB total)

---

## 1. Raw Corpus Verification

Raw CSV headers (`head -n 1`) and line counts (`wc -l`) were verified directly on disk and cross-checked against `reports/dataset_audit.txt`:

| Raw CSV File | Size (Disk) | Data Rows | Missing Cells | Infinite Numeric Values | Attack Families Present |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `Monday-WorkingHours.pcap_ISCX.csv` | 169M (168.7 MB) | 529,918 | 64 | 810 | BENIGN only (529,918) |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 129M (128.8 MB) | 445,909 | 201 | 327 | FTP-Patator (7,938), SSH-Patator (5,897) |
| `Wednesday-workingHours.pcap_ISCX.csv` | 215M (214.7 MB) | 692,703 | 1,008 | 1,586 | DoS Hulk (231,073), GoldenEye (10,293), slowloris (5,796), Slowhttptest (5,499), Heartbleed (11) |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 50M (49.6 MB) | 170,366 | 20 | 250 | Web Attack Brute Force (1,507), XSS (652), Sql Injection (21) |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 80M (79.3 MB) | 288,602 | 18 | 396 | Infiltration (36) |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 56M (55.6 MB) | 191,033 | 28 | 216 | Bot (1,966) |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 74M (73.3 MB) | 286,467 | 15 | 727 | PortScan (158,930) |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 74M (73.6 MB) | 225,745 | 4 | 64 | DDoS (128,027) |
| **Total Raw Corpus** | **844M** | **2,830,743** | **1,358** | **4,376** | **14 Attack Labels + BENIGN** |

**Key Observation:** The full CIC-IDS2017 `MachineLearningCVE` corpus (all 8 capture days, 2,830,743 flows) is physically present on disk, not a small sample.

---

## 2. Schema, Features & Encoding Details

- **Raw Columns:** Each CSV has **79 columns** (78 numeric flow-statistics features + `Label`). Note: `MachineLearningCVE` CSVs already omit `Flow ID`, `Source IP`, `Destination IP`, `Source Port`, and `Timestamp`; `src/preprocess.py` keeps `DROP_COLS` as a defensive `if c in df.columns` check (`L71-77`, `L109-111`).
- **Header Whitespace:** Raw CSV column headers contain leading spaces (e.g., `" Destination Port"`, `" Label"`). Both `audit_dataset.py` and `preprocess.py` strip headers via `.str.strip()`.
- **Duplicate Feature Column:** All 8 raw CSVs list `Fwd Header Length` twice; pandas deduplicates the second occurrence to `Fwd Header Length.1` (index 55 in `data/processed/features.json`).
- **Constant Columns:** `README.md` (line 120) documents 8 zero-variance/constant columns in the 78-feature schema (`Bwd PSH Flags`, `Bwd URG Flags`, and the 6 `*Bulk*` features). These are retained in `features.json` for schema parity with the trained models.
- **Label Encoding Mojibake:** Raw `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` uses Windows-1252 (`cp1252`) byte `0x96` for the en-dash in `Web Attack – *`. When `preprocess.py` previously read UTF-8 with replacement, `data/processed/label_map.json` and `withheld.parquet` stored `\ufffd` (`Web Attack  Brute Force`). The current `preprocess.py` decodes as `cp1252` and matches withheld labels by prefix (`WITHHELD_PREFIXES = ("Infiltration", "Web Attack")`), while `config.pretty_label()` repairs both `\ufffd` and `\x96` at display time.

---

## 3. Preprocessing Pipeline (`src/preprocess.py`)

1. **Chunked Loading (`_load_all_csvs`)**: Reads all 8 CSVs in 100,000-row chunks (`encoding="cp1252"`, `encoding_errors="replace"`), stripping column names.
2. **Cleaning (`_clean`)**:
   - Drops any columns in `DROP_COLS` if present.
   - Strips label strings.
   - Replaces `+Inf` and `-Inf` with `NaN`, then fills all numeric `NaN`s with `0` (4,376 infinities + 1,358 missing cells).
   - Drops exact-duplicate rows via `df.drop_duplicates()`, removing **308,381** duplicates and leaving **2,522,362** unique flows (reported in `TECHNICAL_PROJECT_REPORT.md` Section 8.2 and confirmed by the sum of processed splits: `1,512,109 + 504,037 + 504,037 + 2,179 = 2,522,362`).
3. **Label Encoding (`_encode_labels`)**:
   - Fits `LabelEncoder` across all 15 labels (`0`..`14` in `label_map.json`): `0=BENIGN`, `1=Bot`, `2=DDoS`, `3=DoS GoldenEye`, `4=DoS Hulk`, `5=DoS Slowhttptest`, `6=DoS slowloris`, `7=FTP-Patator`, `8=Heartbleed`, `9=Infiltration`, `10=PortScan`, `11=SSH-Patator`, `12=Web Attack  Brute Force`, `13=Web Attack  Sql Injection`, `14=Web Attack  XSS`.
   - Adds binary `is_attack` (`0` = `BENIGN`, `1` = any attack).
4. **Withheld-Category Isolation (`_split_withheld`)**:
   - Extracts all rows whose `Label` starts with `"Infiltration"` or `"Web Attack"` into `data/processed/withheld.parquet` (**2,179 flows**: Brute Force 1,470, XSS 652, Infiltration 36, SQL Injection 21).
   - Retains **2,520,183** known-category flows (`2,096,484` BENIGN = 83.19%, `423,699` known attacks = 16.81%).
5. **Stratified Splitting (`_stratified_split`)**:
   - Two-stage `train_test_split(..., stratify=label_code, random_state=42)` producing:
     - `train.parquet` (60%): **1,512,109** flows (`1,257,890` BENIGN, `254,219` attacks)
     - `val.parquet` (20%): **504,037** flows (`419,297` BENIGN, `84,740` attacks)
     - `test.parquet` (20%): **504,037** flows (`419,297` BENIGN, `84,740` attacks)
   - *Note:* Direct Parquet reading via `.venv/bin/python3` failed during this audit because host Python upgraded to `3.14.4` while `.venv` packages target `python3.12`; exact split counts are cross-verified from `reports/eval_results.json` (`n_rows: 504037`, `total_withheld_rows: 2179`), `models/rf_eval.json` (`val_rows: 504037`), `models/iforest_eval.json` (`val_rows: 504037`), and `TECHNICAL_PROJECT_REPORT.md` Section 9.3.

---

## 4. Class Imbalance & Data Leakage Assessment

### Class Imbalance
- Severe natural imbalance exists: `BENIGN` is 83.19% of known flows, while minority classes are tiny (`Heartbleed` has 11 raw flows -> ~2 in test; `Infiltration` has 36 withheld flows; `Web Attack – Sql Injection` has 21).
- Mitigated in Random Forest via `class_weight="balanced"` (`train_rf.py` L94) and stratified splitting (`preprocess.py` L178–183).

### Data Leakage & Methodology Assessment
- **Mitigated Leakage Risks:**
  1. Exact duplicates (308,381 rows) were removed *before* splitting (`preprocess.py` L125), preventing identical flows from appearing in both train and test.
  2. `StandardScaler` was fit exclusively on `X_train` (`train_rf.py` L86).
  3. Isolation Forest was fit exclusively on `BENIGN` rows in `train.parquet` (`train_iforest.py` L72–88), and its threshold (`0.061102`) was tuned on `val.parquet` (`L93–105`), keeping `test.parquet` and `withheld.parquet` untouched.
  4. Socket identifiers (`DROP_COLS`) are absent from all model inputs.
- **Remaining Subtle Risks / Caveats:**
  1. **Random Stratified Split vs. Temporal/Capture-Day Split:** Splitting randomly across all capture days means flows from the same attack session/burst (e.g., same Wednesday DoS Hulk campaign) are shared across train, val, and test. This makes known-attack test scores optimistic compared to unseen capture days.
  2. **Imputation Before Split (`preprocess.py` L118–120):** Replacing `NaN`/`Inf` with `0` globally before splitting leaks zero information because `0` is a constant (no dataset statistics computed).
  3. **Known CIC-IDS2017 Dataset Artifacts (Literature):** `Destination Port` remains in the 78 features; tree models can partially anchor on server ports (e.g., 80, 21, 22), and CIC-IDS2017 itself contains known flow-labeling quirks documented in Engelen et al. (2021) and Lanvin et al. (2023).
  4. **Withheld Sample Size:** `Infiltration` has only 36 flows and `SQL Injection` only 21, limiting statistical precision on withheld recall rates.
