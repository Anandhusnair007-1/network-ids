# Runbook

## Daily
1. Open **Incidents** and **Alert history**, work HIGH then MEDIUM. Record a verdict on each (Confirm attack or Mark false positive).
2. Check **Detector health**. Input drift "significant" means the traffic no longer looks like the training baseline.

## Alert volume suddenly jumps
Check drift first. If PSI is high, the network changed (new service, new sensor, export settings), not necessarily an attack.
Compare with `GET /v1/stats` by severity. A true attack usually concentrates in one or two labels and a few source IPs.

## Retraining
1. `GET /v1/feedback/export` returns analyst-labelled flows (confirmed becomes the attack label, false positives become BENIGN).
2. Review the export, then merge it with the original training data. Do not train on feedback alone.
3. `make train-rf train-iforest evaluate`, compare against `reports/eval_results.json`, then `make manifest drift-reference`
   and `make sign`. Restart the services.
4. Roll back by restoring the previous `models/` directory and its signed manifest.

## Failure modes
| Symptom | Likely cause | Action |
|---|---|---|
| API exits at start with "Refusing to start" | No `IDS_API_KEYS` | Set keys in `.env` |
| API exits with manifest error | A model file or the manifest changed, or the signature is missing | Restore from backup. Do not run `make manifest` unless you made the change |
| 401 on every call | Wrong or missing key header | Use `X-API-Key` or `Authorization: Bearer` |
| 413 | Body over `IDS_MAX_UPLOAD_BYTES` or rows over `IDS_MAX_UPLOAD_ROWS` | Split the file |
| `ids_sink_failed_alerts` rising | SIEM unreachable or rejecting | Alerts stay in the database. Fix the sink, then re-export by querying `/v1/alerts` |
| Files piling up in `rejected/` | Wrong columns or encoding | Read the `.reason.txt` beside each file |
| `/readyz` returns 503 | Database not writable | Check the `var/` volume permissions and disk space |

## Backups
Back up `var/ids.sqlite3` (use `sqlite3 var/ids.sqlite3 ".backup backup.db"` while running) and the signed `models/` directory.
