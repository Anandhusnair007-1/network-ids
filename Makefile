# Network IDS — Makefile
# Run targets from the project root.

PYTHON := .venv/bin/python3
PIP    := .venv/bin/python3 -m pip

.PHONY: install audit preprocess train-rf train-iforest evaluate test dashboard all

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

## Run unit tests
test:
	.venv/bin/pytest tests/ -v

## Launch the Streamlit dashboard
dashboard:
	.venv/bin/streamlit run dashboard/app.py

## Full pipeline: preprocess -> train RF -> train IF -> evaluate
all: preprocess train-rf train-iforest evaluate
	@echo "Full pipeline complete. Run 'make dashboard' to start the UI."
