"""
api/main.py
===========
Scoring API for the hybrid Network IDS.

    uvicorn api.main:app --host 0.0.0.0 --port 8000

Security posture
----------------
* Secure by default: the app refuses to start with no API keys unless IDS_API_ALLOW_ANON=true.
* API keys via ``X-API-Key`` or ``Authorization: Bearer`` (constant-time comparison); per-key rate limit.
* Request bodies are capped while streaming (not just by Content-Length).
* Every request is written to a JSON-lines audit log with the key *fingerprint*, never the key.
* Errors never leak tracebacks; clients get a request id to quote to the operator.
* Alert/SIEM destinations are operator-configured only (no SSRF through request data).

Endpoints
---------
GET  /healthz            liveness (no auth)
GET  /readyz             models loaded and store reachable (no auth)
GET  /metrics            Prometheus metrics (auth unless IDS_METRICS_PUBLIC=true)
GET  /v1/policies        available alert policies
POST /v1/score           score flows posted as JSON
POST /v1/score/csv       score an uploaded flow CSV
GET  /v1/alerts          list stored alerts (filter by severity / status)
GET  /v1/alerts/{id}     one alert
POST /v1/alerts/{id}/status   analyst verdict (acknowledged | confirmed | false_positive)
GET  /v1/stats           alert counts
GET  /v1/feedback/export analyst-labelled flows as CSV, for retraining
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import logging.handlers
import os
import sys
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import pandas as pd
from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import config as cfg  # noqa: E402
from policy import POLICY_INFO  # noqa: E402
from service import ScoringService  # noqa: E402
from store import STATUSES  # noqa: E402
from validator import OversizedInputError, ValidationError  # noqa: E402

API_VERSION = "1.0.0"


# -- Request/response models --------------------------------------------------
class ScoreRequest(BaseModel):
    flows: list[dict[str, float | int | str | None]] = Field(..., min_length=1)
    policy: str | None = None
    persist: bool = True
    fill_missing: bool = False


class StatusUpdate(BaseModel):
    status: str
    note: str = Field("", max_length=1000)


# -- Pure-ASGI body limiter (counts streamed bytes, so chunked uploads cannot dodge Content-Length) -------
class BodyLimitMiddleware:
    def __init__(self, app: Callable, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return
        seen = 0

        async def limited_receive() -> dict:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._reject(send)

    async def _reject(self, send: Callable) -> None:
        body = json.dumps({"detail": f"Request body exceeds {self.max_bytes} bytes"}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class _BodyTooLarge(Exception):
    pass


class RateLimiter:
    """Sliding-window limiter, per API-key fingerprint. In-memory: use the reverse proxy for multi-replica limits."""

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, ident: str) -> float:
        """Return 0 if allowed, else seconds until the next slot."""
        if self.per_minute <= 0:
            return 0.0
        now, window = time.monotonic(), self.hits[ident]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= self.per_minute:
            return max(60 - (now - window[0]), 1.0)
        window.append(now)
        return 0.0


def _fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:10]


def _audit_logger(path: Path | None) -> logging.Logger:
    logger = logging.getLogger(f"ids.audit.{id(path)}.{uuid.uuid4().hex[:6]}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8")
    else:
        handler = logging.NullHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def create_app(
    service_factory: Callable[[], ScoringService] = ScoringService.from_config,
    api_keys: tuple[str, ...] | None = None,
    allow_anon: bool | None = None,
    rate_limit_per_min: int | None = None,
    audit_path: Path | None = cfg.AUDIT_LOG_PATH,
    max_body_bytes: int = cfg.MAX_UPLOAD_BYTES,
    metrics_public: bool | None = None,
) -> FastAPI:
    keys = tuple(cfg.API_KEYS if api_keys is None else api_keys)
    anon = cfg.API_ALLOW_ANON if allow_anon is None else allow_anon
    public_metrics = cfg.API_METRICS_PUBLIC if metrics_public is None else metrics_public
    limiter = RateLimiter(cfg.API_RATE_LIMIT_PER_MIN if rate_limit_per_min is None else rate_limit_per_min)
    audit = _audit_logger(audit_path)

    registry = CollectorRegistry()
    m_flows = Counter("ids_flows_scored_total", "Flows scored", registry=registry)
    m_alerts = Counter("ids_alerts_total", "Alerts raised", ["severity"], registry=registry)
    m_req = Counter("ids_http_requests_total", "HTTP requests", ["method", "route", "status"], registry=registry)
    m_lat = Histogram("ids_score_seconds", "Scoring latency per request", registry=registry,
                      buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30))
    m_sink_fail = Gauge("ids_sink_failed_alerts", "Alerts the SIEM sinks failed to deliver", registry=registry)
    m_drift = Gauge("ids_drift_median_psi", "Median feature PSI of the last scored batch", registry=registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not keys and not anon:
            raise RuntimeError(
                "Refusing to start without authentication. Set IDS_API_KEYS=<key1,key2> "
                "(or IDS_API_ALLOW_ANON=true for local development only).")
        app.state.service = await run_in_threadpool(service_factory)
        yield
        app.state.service.store.close()

    docs = "/docs" if os.getenv("IDS_API_DOCS", "").lower() in ("1", "true", "yes") else None
    app = FastAPI(title="Network IDS API", version=API_VERSION, lifespan=lifespan,
                  docs_url=docs, redoc_url=None, openapi_url="/openapi.json" if docs else None)
    app.add_middleware(BodyLimitMiddleware, max_bytes=max_body_bytes)

    # -- auth ----------------------------------------------------------------
    def authenticate(request: Request) -> str:
        presented = request.headers.get("x-api-key", "")
        auth = request.headers.get("authorization", "")
        if not presented and auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
        ident = "anonymous"
        if keys:
            matched = False
            for k in keys:  # compare against every key: no early exit that leaks which one matched
                matched |= hmac.compare_digest(presented.encode(), k.encode())
            if not matched:
                raise HTTPException(status_code=401, detail="Missing or invalid API key",
                                    headers={"WWW-Authenticate": "Bearer"})
            ident = _fingerprint(presented)
        wait = limiter.check(ident)
        if wait:
            raise HTTPException(status_code=429, detail="Rate limit exceeded",
                                headers={"Retry-After": str(int(wait) + 1)})
        request.state.key_id = ident
        return ident

    def svc(request: Request) -> ScoringService:
        return request.app.state.service

    # -- request audit + metrics + headers --------------------------------------
    @app.middleware("http")
    async def observe(request: Request, call_next):
        rid = uuid.uuid4().hex[:12]
        request.state.request_id, request.state.key_id, request.state.n_rows = rid, "-", None
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:  # noqa: BLE001 - last-resort handler, details go to the log only
            logging.getLogger("ids.api").exception("Unhandled error [%s]", rid)
            response = JSONResponse({"detail": "Internal error", "request_id": rid}, status_code=500)
        ms = (time.perf_counter() - start) * 1000
        route = request.scope.get("route")
        path_tpl = getattr(route, "path", request.url.path if response.status_code == 404 else "unmatched")
        m_req.labels(request.method, path_tpl, str(response.status_code)).inc()
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        audit.info(json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "request_id": rid,
            "key": request.state.key_id, "method": request.method, "path": request.url.path,
            "status": response.status_code, "ms": round(ms, 1), "rows": request.state.n_rows,
            "client": request.client.host if request.client else None,
        }))
        return response

    @app.exception_handler(OversizedInputError)
    async def _oversize(_: Request, exc: OversizedInputError):
        return JSONResponse({"detail": str(exc)}, status_code=413)

    @app.exception_handler(ValidationError)
    async def _invalid(_: Request, exc: ValidationError):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    # -- helpers ----------------------------------------------------------------
    def run_scoring(request: Request, df: pd.DataFrame, source: str, policy: str | None,
                    persist: bool, fill_missing: bool) -> dict[str, Any]:
        request.state.n_rows = len(df)
        if policy is not None and policy not in POLICY_INFO:
            raise HTTPException(status_code=400, detail=f"Unknown policy. Valid: {sorted(POLICY_INFO)}")
        t0 = time.perf_counter()
        out = svc(request).score(df, source=source, policy=policy, persist=persist, fill_missing=fill_missing)
        m_lat.observe(time.perf_counter() - t0)
        m_flows.inc(out.summary["flows"])
        for sev, n in out.summary["by_severity"].items():
            if sev != "INFO" and n:
                m_alerts.labels(sev).inc(n)
        m_sink_fail.set(svc(request).sinks.failed)
        if out.drift and "median_psi" in out.drift:
            m_drift.set(out.drift["median_psi"])
        res = out.results
        alert_for = dict(zip(res.index[res["severity"] != "INFO"], out.alert_ids, strict=False)) if out.alert_ids else {}
        results = [
            {"index": int(i), "severity": r["severity"], "label": r["final_label"], "classifier": r["rf_label"],
             "confidence": round(float(r["rf_confidence"]), 4), "anomaly_score": round(float(r["anomaly_score"]), 4),
             **({"alert_id": alert_for[i]} if i in alert_for else {})}
            for i, r in res.iterrows()
        ]
        return {"summary": out.summary, "drift": out.drift, "results": results}

    # -- public probes ---------------------------------------------------------------
    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": API_VERSION}

    @app.get("/readyz", tags=["ops"])
    def readyz(request: Request) -> JSONResponse:
        try:
            svc(request).store.stats()
            return JSONResponse({"status": "ready"})
        except Exception:  # noqa: BLE001
            return JSONResponse({"status": "not_ready"}, status_code=503)

    @app.get("/metrics", tags=["ops"], include_in_schema=False)
    def metrics(request: Request) -> Response:
        if not public_metrics:
            authenticate(request)
        return PlainTextResponse(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    # -- v1 ------------------------------------------------------------------------------
    @app.get("/v1/policies", tags=["scoring"])
    def policies(_: str = Depends(authenticate)) -> dict[str, Any]:
        return {"policies": {k: {"label": v["label"], "summary": v["summary"]} for k, v in POLICY_INFO.items()}}

    @app.post("/v1/score", tags=["scoring"])
    def score(body: ScoreRequest, request: Request, _: str = Depends(authenticate)) -> dict[str, Any]:
        if len(body.flows) > cfg.MAX_UPLOAD_ROWS:
            raise OversizedInputError(f"Batch of {len(body.flows):,} flows exceeds limit of {cfg.MAX_UPLOAD_ROWS:,}")
        return run_scoring(request, pd.DataFrame(body.flows), "api:json", body.policy, body.persist, body.fill_missing)

    @app.post("/v1/score/csv", tags=["scoring"])
    async def score_csv(request: Request, file: UploadFile = File(...), policy: str | None = Form(None),
                        persist: bool = Form(True), fill_missing: bool = Form(False),
                        _: str = Depends(authenticate)) -> dict[str, Any]:
        raw = await file.read(cfg.MAX_UPLOAD_BYTES + 1)
        if len(raw) > cfg.MAX_UPLOAD_BYTES:
            raise OversizedInputError(f"File exceeds {cfg.MAX_UPLOAD_BYTES // 2**20} MB")
        try:
            df = pd.read_csv(io.BytesIO(raw), nrows=cfg.MAX_UPLOAD_ROWS + 1, low_memory=False,
                             encoding="utf-8", encoding_errors="replace")
        except (pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
            raise ValidationError(f"Could not parse CSV: {exc}") from exc
        df.columns = df.columns.astype(str).str.strip()
        if len(df) > cfg.MAX_UPLOAD_ROWS:
            raise OversizedInputError(f"CSV has more than {cfg.MAX_UPLOAD_ROWS:,} rows")
        safe_name = Path(file.filename or "upload.csv").name[:80]
        return await run_in_threadpool(run_scoring, request, df, f"api:csv:{safe_name}", policy, persist, fill_missing)

    @app.get("/v1/alerts", tags=["alerts"])
    def list_alerts(request: Request, severity: list[str] | None = Query(None), status: str | None = None,
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                    _: str = Depends(authenticate)) -> dict[str, Any]:
        if status is not None and status not in STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {STATUSES}")
        return {"alerts": svc(request).store.list_alerts(severity, status, limit, offset)}

    @app.get("/v1/alerts/{alert_id}", tags=["alerts"])
    def get_alert(alert_id: str, request: Request, _: str = Depends(authenticate)) -> dict[str, Any]:
        row = svc(request).store.get_alert(alert_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        row.pop("features_json", None)
        return row

    @app.post("/v1/alerts/{alert_id}/status", tags=["alerts"])
    def update_status(alert_id: str, body: StatusUpdate, request: Request,
                      _: str = Depends(authenticate)) -> dict[str, Any]:
        if body.status not in STATUSES:
            raise HTTPException(status_code=400, detail=f"status must be one of {STATUSES}")
        if not svc(request).store.set_status(alert_id, body.status, body.note):
            raise HTTPException(status_code=404, detail="Alert not found")
        return {"alert_id": alert_id, "status": body.status}

    @app.get("/v1/stats", tags=["alerts"])
    def stats(request: Request, _: str = Depends(authenticate)) -> dict[str, Any]:
        return svc(request).store.stats()

    @app.get("/v1/feedback/export", tags=["alerts"])
    def feedback_export(request: Request, _: str = Depends(authenticate)) -> Response:
        df = svc(request).store.export_feedback()
        return Response(df.to_csv(index=False), media_type="text/csv",
                        headers={"Content-Disposition": 'attachment; filename="analyst_feedback.csv"'})

    return app


# Module-level app for ``uvicorn api.main:app``. Models load in the lifespan, not at import.
app = create_app()
