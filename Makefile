# Network IDS — Makefile
# Run targets from the project root.

PYTHON := .venv/bin/python3
PIP    := .venv/bin/python3 -m pip

.PHONY: install audit preprocess train-rf train-iforest evaluate test lint verify-artifacts check quality-gate dashboard all

## Install dependencies into the virtual environment
install:
	$(PIP) install -r requirements.txt

## Audit the raw dataset (quick sanity check, no modifications)
audit:
	$(PYTHON) src/audit_dataset.py

## Step 1 – Preprocess: clean + split raw CSVs -> data/processed/
preprocess:
	$(PYTHON) src/preprocess.py

## Step 2 – Train the Random Forest classifier
train-rf:
	$(PYTHON) src/train_rf.py

## Step 3 – Train the Isolation Forest anomaly detector
train-iforest:
	$(PYTHON) src/train_iforest.py

## Step 4 – Run hybrid evaluation (known + withheld categories)
evaluate:
	$(PYTHON) src/evaluate_hybrid.py

## Verify SHA-256 cryptographic integrity of all saved model artifacts
verify-artifacts:
	$(PYTHON) src/security.py

## Code style and linting gate
lint:
	$(PYTHON) -m ruff check --line-length 120 --select F,E,W --ignore E501 src/ dashboard/ tests/

## Run automated test suite (unit, security, and integration tests)
test:
	$(PYTHON) -m pytest tests/ -v

## Automated Release Quality Gate: verify artifacts, lint, compile, dependencies, and test suite
check: verify-artifacts lint
	@echo "Checking Python bytecode compilation..."
	$(PYTHON) -m compileall -q src dashboard tests
	@echo "Checking pip dependency consistency..."
	$(PIP) check
	@echo "Executing full test suite..."
	$(PYTHON) -m pytest tests/ -v
	@echo "============================================================"
	@echo "  ALL QUALITY GATES PASSED (Integrity, Lint, Deps, Tests)"
	@echo "============================================================"

quality-gate: check

## Launch the Streamlit dashboard
dashboard:
	$(PYTHON) -m streamlit run dashboard/app.py

## Full pipeline: preprocess -> train RF -> train IF -> evaluate
all: preprocess train-rf train-iforest evaluate
	@echo "Full pipeline complete. Run 'make dashboard' to start the UI."

