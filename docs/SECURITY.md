# Security model

## Assets and trust boundaries
Model files (pickles execute code when loaded), the API, the incident database, SIEM credentials, analyst accounts.
Flow data from the network is untrusted. Model files and the manifest are trusted only after verification.

## Controls in place
| Threat | Control | Where |
|---|---|---|
| Tampered or swapped model pickle | SHA-256 manifest checked before any unpickling | `src/security.py` |
| Attacker rewrites model and manifest together | Ed25519 signature on the manifest, enforced when `IDS_MANIFEST_PUBKEY` is set | `src/signing.py` |
| Unauthenticated API use | API keys (constant-time compare over all keys), refuses to start with none | `api/main.py` |
| Abuse and brute force | Per-key rate limit (429 with Retry-After) | `api/main.py` |
| Memory exhaustion | Body cap counted on streamed bytes, row cap, file-size cap | `BodyLimitMiddleware`, `validator.py` |
| Malformed or hostile input | Strict schema validation, NaN/inf rejection, no zero-fill unless asked | `src/validator.py` |
| SQL injection | Parameterised queries only; tested with hostile input | `src/store.py` |
| SSRF through the API | Webhook and syslog targets come only from operator config | `src/sinks.py` |
| Log or CEF injection | Newline and delimiter escaping | `src/sinks.py` |
| Forged webhooks | HMAC-SHA256 signature header | `src/sinks.py` |
| Path tricks on ingest | Symlinks refused, uploads use `Path.name` only, rejected files quarantined with a reason | `src/ingest_dir.py` |
| Audit | JSON-lines log with request id, key fingerprint (never the key), status, rows, latency | `var/audit.log` |
| Information leaks | No tracebacks to clients, OpenAPI docs off by default, `no-store`, `nosniff` | `api/main.py` |
| Container escape | Non-root user, read-only filesystem, all capabilities dropped | `Dockerfile`, compose |
| Code and dependency flaws | ruff, bandit (medium+ fails), pip-audit in CI | `.github/workflows/ci.yml` |

## Signing the manifest
```bash
make keygen                     # writes keys/manifest_private.pem and manifest_public.pem
make sign                       # signs models/manifest.json
export IDS_MANIFEST_PUBKEY=keys/manifest_public.pem
```
Keep the private key off the serving host (a build machine, HSM or cloud KMS). The serving host needs only the public key.

## Residual risks
* **Pickle is the weak point.** Verification narrows it but does not remove it. Exporting the models to ONNX removes code
  execution from the load path and is the recommended next step.
* **API keys are shared secrets with no roles.** Anyone with a key can change alert verdicts. Use SSO and per-user
  identity at the proxy for a multi-analyst deployment.
* **Dashboard login is a single shared password** with in-session delay only. Put real SSO in front for production.
* **Evasion:** an attacker who can shape their traffic can try to stay under the classifier's confidence and anomaly
  thresholds. Adversarial robustness was not tested.
* **Data poisoning:** the analyst feedback export feeds retraining. Review exports before training on them.
* No penetration test or external security review has been done.
