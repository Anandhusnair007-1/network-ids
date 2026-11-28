# Deployment

## Components
| Piece | Entry point | Port | Purpose |
|---|---|---|---|
| Scoring API | `uvicorn api.main:app` | 8000 | Score flows (JSON or CSV), list alerts, record analyst verdicts, export retraining data, `/metrics` |
| Dashboard | `streamlit run dashboard/app.py` | 8501 | Analyst console: scan, incidents, alert history, detector health and drift |
| Folder ingestor | `python src/ingest_dir.py` | none | Scores every CSV dropped into `var/ingest/inbox/` |
| Incident store | SQLite (WAL) at `var/ids.sqlite3` | none | Alerts, batches, verdicts |

## Quick start (single host)
```bash
cp .env.example .env            # set IDS_API_KEYS and IDS_DASH_PASSWORD_SHA256
make all                        # train + manifest + evaluate (skip if models/ already exists)
make drift-reference            # baseline for drift monitoring
docker compose up -d            # api on 127.0.0.1:8000, dashboard on 127.0.0.1:8501
docker compose --profile ingest up -d ingest
```
Both ports bind to localhost. Put a reverse proxy (nginx, Caddy, Traefik) with TLS in front. Never expose them directly.

## Scoring a batch
```bash
curl -H "X-API-Key: $KEY" -F file=@flows.csv -F policy=tiered https://ids.example.org/v1/score/csv
```
JSON flows go to `POST /v1/score` with `{"flows": [{...78 features...}]}`. Set `"persist": false` for a dry run.

## SIEM export
Set `IDS_SYSLOG_ADDR=host:514` for CEF over UDP syslog (Splunk, QRadar, ArcSight, Sentinel) and/or `IDS_WEBHOOK_URL` plus
`IDS_WEBHOOK_SECRET` for an HMAC-SHA256 signed webhook (`X-IDS-Signature`). Only alerts at or above `IDS_SINK_MIN_SEVERITY`
(default MEDIUM) are sent. A failed delivery is logged and counted (`ids_sink_failed_alerts`) and never blocks scoring.

## Monitoring
Scrape `/metrics` (API key required): `ids_flows_scored_total`, `ids_alerts_total{severity}`, `ids_score_seconds`,
`ids_http_requests_total`, `ids_drift_median_psi`, `ids_sink_failed_alerts`. Suggested alerts: drift PSI above 0.25 for
an hour, sink failures above 0, 5xx rate above 1%, `/readyz` failing.

## Known limits
* SQLite and the in-memory rate limiter suit one API instance. For several replicas move the store to PostgreSQL and the
  limiter to the proxy or Redis.
* Docker image tested on 2026-11-28 (Docker 29.9.3, overlay2, local host): `docker build -t network-ids:ci .` succeeds (798 MB image). Run with the hardening used in `docker-compose.yml` (`--read-only`, `--tmpfs /tmp`, `--cap-drop ALL`, `no-new-privileges`, models and processed data mounted read-only), the API container runs as uid 10001 (`ids`), reports `healthy` through its HEALTHCHECK, answers `/healthz` and `/readyz`, returns 401 without a key and 422 on a malformed flow, and cannot write outside `/app/var` and `/tmp`. Under the same load test as report section 11.6 it returned HTTP 200 for every request (about 7,500 flows/s at 1,000-flow batches, 22 flows/s at one flow per request, about 335 MiB memory). The dashboard container started and `/_stcore/health` returned `ok`. `docker compose up` itself, the `ingest` profile and a multi-container deployment were not run. The GitHub Actions workflow (`.github/workflows/ci.yml`) has still never executed a step (runs #1-#11) because the GitHub account is locked for a billing issue; once billing is restored it will rebuild the image on every push to `main`.
* Measured hybrid scoring speed (`make benchmark`, AMD Ryzen 7 6800H): about 66,000 flows/s at 10,000-flow batches and 98,700 flows/s at 50,000, model only.
* Measured API load (one uvicorn worker, loopback, `persist=false`): about 8,800 flows/s at 1,000-flow batches, 24 flows/s at one flow per request, with no errors over 1,744 requests. Throughput does not rise with concurrency, so run several workers or replicas. Details in `reports/TECHNICAL_PROJECT_REPORT.md` section 11.6. SQLite write rate, the CSV endpoint and real network load were not load tested.
