"""
src/ingest_dir.py
=================
Folder ingestor: score every flow CSV that a flow exporter (CICFlowMeter, a Zeek post-processor, ...)
drops into an inbox directory.

    python src/ingest_dir.py                 # watch forever
    python src/ingest_dir.py --once          # process what is there and exit (cron / tests)

    var/ingest/inbox/      <- exporter writes here
    var/ingest/processed/  <- scored files
    var/ingest/rejected/   <- invalid files, each with a <name>.reason.txt

Hardening: regular files only (no symlinks), size cap, files still being written are skipped, large
files are streamed in chunks so memory stays flat, and a bad file never stops the loop.
"""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import MAX_UPLOAD_ROWS, VAR_DIR  # noqa: E402
from service import ScoringService  # noqa: E402
from validator import ValidationError  # noqa: E402

log = logging.getLogger("ids.ingest")
SETTLE_SECONDS = 2.0
MAX_INGEST_BYTES = 2 * 1024 * 1024 * 1024   # streamed in chunks, so far larger than an interactive upload


def _move(path: Path, dest_dir: Path, reason: str | None = None) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    target = dest_dir / f"{int(time.time())}_{path.name}"
    shutil.move(str(path), str(target))
    if reason:
        target.with_suffix(target.suffix + ".reason.txt").write_text(reason + "\n", encoding="utf-8")


def process_file(service: ScoringService, path: Path, processed: Path, rejected: Path) -> dict:
    """Score one CSV. Returns {'flows', 'alerts', 'status'}; never raises for bad input."""
    try:
        if path.is_symlink() or not path.is_file():
            raise ValidationError("not a regular file")
        if path.stat().st_size > MAX_INGEST_BYTES:
            raise ValidationError(f"file exceeds {MAX_INGEST_BYTES // 2**20} MB")
        flows = alerts = 0
        reader = pd.read_csv(path, chunksize=MAX_UPLOAD_ROWS, low_memory=False,
                             encoding="utf-8", encoding_errors="replace")
        for i, chunk in enumerate(reader):
            chunk.columns = chunk.columns.astype(str).str.strip()
            out = service.score(chunk, source=f"ingest:{path.name}#{i}")
            flows += out.summary["flows"]
            alerts += out.summary["alerts"]
        _move(path, processed)
        log.info("Ingested %s: %d flows, %d alerts", path.name, flows, alerts)
        return {"flows": flows, "alerts": alerts, "status": "processed"}
    except (ValidationError, pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeError, ValueError) as exc:
        log.warning("Rejected %s: %s", path.name, exc)
        _move(path, rejected, str(exc))
        return {"flows": 0, "alerts": 0, "status": "rejected"}


def run(service: ScoringService, root: Path, once: bool = False, interval: float = 5.0) -> None:
    inbox, processed, rejected = root / "inbox", root / "processed", root / "rejected"
    for d in (inbox, processed, rejected):
        d.mkdir(parents=True, exist_ok=True)
    while True:
        for path in sorted(inbox.glob("*.csv")):
            if time.time() - path.stat().st_mtime < SETTLE_SECONDS:
                continue   # exporter may still be writing it
            process_file(service, path, processed, rejected)
        if once:
            return
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=VAR_DIR / "ingest")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--interval", type=float, default=5.0)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    run(ScoringService.from_config(), args.root, args.once, args.interval)


if __name__ == "__main__":
    main()
