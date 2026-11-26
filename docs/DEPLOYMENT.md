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
* The Docker image was not built or run in the development environment (no Docker daemon). CI builds it on every push.
* Scoring speed on 2 CPU cores was about 47,000 flows/s for the model alone. API throughput, SQLite write rate and
  real network load were not load tested.
