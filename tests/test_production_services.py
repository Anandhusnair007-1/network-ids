"""Tests for the production layer: store, sinks, drift, signing, service, ingest and the HTTP API."""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import sys
import threading
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

import config as cfg  # noqa: E402
import drift  # noqa: E402
import signing  # noqa: E402
from sinks import SinkManager, SyslogCEFSink, WebhookSink, to_cef  # noqa: E402
from store import IncidentStore  # noqa: E402

needs_artifacts = pytest.mark.skipif(
    not (cfg.MODELS_DIR / "rf_model.pkl").exists() or not (cfg.DATA_DIR / "features.json").exists(),
    reason="trained models / processed data not present (CI without artifacts)",
)


# -- synthetic scored frame (no model needed) -----------------------------------------
def scored_frame() -> pd.DataFrame:
    return pd.DataFrame({
        "Source IP": ["10.0.0.5", "10.0.0.5", "10.0.0.9", "10.0.0.7"],
        "Destination IP": ["8.8.8.8", "8.8.8.8", "1.1.1.1", "1.1.1.1"],
        "rf_label": ["DDoS", "DDoS", "BENIGN", "PortScan"],
        "rf_confidence": [0.99, 0.97, 0.9, 0.8],
        "anomaly_score": [-0.1, -0.05, 0.2, 0.01],
        "final_label": ["DDoS", "DDoS", "BENIGN", "PortScan"],
        "severity": ["HIGH", "HIGH", "INFO", "MEDIUM"],
        "f1": [1.0, 2.0, 3.0, 4.0],
    })


@pytest.fixture
def store(tmp_path):
    s = IncidentStore(tmp_path / "ids.db")
    yield s
    s.close()


class TestStore:
    def test_only_alerts_persisted_and_listed(self, store):
        bid, ids = store.save_batch(scored_frame(), "t", "tiered", ["f1"])
        assert bid and len(ids) == 3
        assert len(store.list_alerts()) == 3
        assert [a["severity"] for a in store.list_alerts(severity=["MEDIUM"])] == ["MEDIUM"]

    def test_status_roundtrip_and_validation(self, store):
        _, ids = store.save_batch(scored_frame(), "t", "tiered", ["f1"])
        assert store.set_status(ids[0], "confirmed", "real")
        assert store.get_alert(ids[0])["status"] == "confirmed"
        assert store.set_status("nope", "confirmed") is False
        with pytest.raises(ValueError):
            store.set_status(ids[0], "bogus")

    def test_feedback_export_labels(self, store):
        _, ids = store.save_batch(scored_frame(), "t", "tiered", ["f1"])
        store.set_status(ids[0], "confirmed")
        store.set_status(ids[2], "false_positive")
        fb = store.export_feedback()
        assert len(fb) == 2
        assert set(fb["Label"]) == {"DDoS", "BENIGN"}

    def test_sql_injection_is_inert(self, store):
        store.save_batch(scored_frame(), "t'; DROP TABLE alerts;--", "tiered", ["f1"])
        assert len(store.list_alerts(severity=["HIGH' OR '1'='1"])) == 0
        assert len(store.list_alerts()) == 3


class TestSinks:
    ALERT = {"alert_id": "a1", "severity": "HIGH", "final_label": "DDoS", "rf_label": "DDoS", "src_ip": "1.2.3.4",
             "dst_ip": "5.6.7.8", "rf_confidence": 0.9, "anomaly_score": -0.1}

    def test_cef_escapes_injection(self):
        line = to_cef({**self.ALERT, "final_label": "x|y\nz=1"})
        assert line.startswith("CEF:0|")
        assert "\n" not in line
        assert "x\\|y" in line

    def test_min_severity_filter(self):
        got = []

        class Cap(SyslogCEFSink):
            def __init__(self):
                pass
            def send(self, alerts): got.extend(alerts)

        mgr = SinkManager([Cap()], "HIGH")
        mgr.dispatch([self.ALERT, {**self.ALERT, "severity": "LOW"}])
        assert len(got) == 1

    def test_webhook_hmac_signature(self):
        seen = {}

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                seen["body"], seen["sig"] = body, self.headers.get("X-IDS-Signature")
                self.send_response(200)
                self.end_headers()
            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            WebhookSink(f"http://127.0.0.1:{srv.server_port}/hook", "s3cret").send([self.ALERT])
        finally:
            srv.shutdown()
        expected = hmac.new(b"s3cret", seen["body"], hashlib.sha256).hexdigest()
        assert seen["sig"].endswith(expected)

    def test_webhook_rejects_bad_scheme(self):
        with pytest.raises(ValueError):
            WebhookSink("file:///etc/passwd")

    def test_sink_failure_never_raises(self):
        mgr = SinkManager([WebhookSink("http://127.0.0.1:1/x", "", timeout=0.5)], "LOW")
        mgr.dispatch([self.ALERT])
        assert mgr.failed == 1


class TestDrift:
    def test_stable_vs_shifted(self):
        rng = np.random.default_rng(0)
        ref_df = pd.DataFrame({"a": rng.normal(0, 1, 5000), "b": rng.normal(5, 2, 5000)})
        ref = drift.build_reference(ref_df, ["a", "b"], rng.normal(0, 1, 5000))
        same = pd.DataFrame({"a": rng.normal(0, 1, 1000), "b": rng.normal(5, 2, 1000)})
        shifted = pd.DataFrame({"a": rng.normal(3, 1, 1000), "b": rng.normal(5, 2, 1000)})
        assert drift.assess(ref, same)["status"] == "stable"
        assert drift.assess(ref, shifted)["status"] in ("moderate", "significant")
        assert drift.assess(ref, same.head(20))["status"] == "insufficient_data"


class TestSigning:
    def test_sign_verify_tamper(self, tmp_path):
        manifest = tmp_path / "manifest.json"
        manifest.write_text('{"a": 1}')
        priv, pub = signing.generate_keypair(tmp_path)
        signing.sign_manifest(priv, manifest)
        signing.verify_manifest_signature(pub, manifest)
        manifest.write_text('{"a": 2}')
        with pytest.raises(signing.SignatureError):
            signing.verify_manifest_signature(pub, manifest)

    def test_private_key_permissions(self, tmp_path):
        priv, _ = signing.generate_keypair(tmp_path)
        assert (priv.stat().st_mode & 0o077) == 0


class TestSignedManifest:
    def test_load_manifest_enforces_signature(self, tmp_path, monkeypatch):
        import security
        manifest = tmp_path / "manifest.json"
        manifest.write_text(json.dumps({"artifacts": {}}))
        priv, pub = signing.generate_keypair(tmp_path)
        monkeypatch.setattr(security, "MANIFEST_PUBKEY", str(pub))
        with pytest.raises(security.ManifestError):          # unsigned
            security.load_manifest(manifest)
        signing.sign_manifest(priv, manifest)
        assert security.load_manifest(manifest) == {"artifacts": {}}
        manifest.write_text(json.dumps({"artifacts": {"x": "tampered"}}))
        with pytest.raises(security.ManifestError):          # edited after signing
            security.load_manifest(manifest)


# -- tests that need the trained models ------------------------------------------------------------------
@pytest.fixture(scope="module")
def real_flows():
    pytest.importorskip("pyarrow")
    feats = json.loads((cfg.DATA_DIR / "features.json").read_text())
    path = next(iter(sorted(cfg.DATA_DIR.glob("*test*.parquet"))), None)
    if path is None:
        pytest.skip("no test parquet")
    df = pd.read_parquet(path)
    df = pd.concat([df[df["Label"] == "BENIGN"].head(150), df[df["Label"] != "BENIGN"].head(150)])
    return df.reset_index(drop=True), feats


@pytest.fixture
def service(tmp_path):
    from service import ScoringService
    from hybrid import HybridDetector
    feats = json.loads((cfg.DATA_DIR / "features.json").read_text())
    s = ScoringService(HybridDetector.load(), feats, IncidentStore(tmp_path / "s.db"), SinkManager(), "tiered",
                       drift.load_reference(cfg.DRIFT_REFERENCE_PATH))
    yield s
    s.store.close()


@needs_artifacts
class TestService:
    def test_score_persists_alerts(self, service, real_flows):
        df, _ = real_flows
        out = service.score(df, "test")
        assert out.summary["flows"] == len(df)
        assert out.summary["alerts"] == len(out.alert_ids) > 0
        assert sum(service.store.stats()["by_severity"].values()) == len(out.alert_ids)

    def test_persist_false_writes_nothing(self, service, real_flows):
        out = service.score(real_flows[0], "test", persist=False)
        assert out.batch_id is None and sum(service.store.stats()["by_severity"].values()) == 0

    def test_unknown_policy_rejected(self, service, real_flows):
        with pytest.raises(KeyError):
            service.score(real_flows[0], "t", policy="nope")


@needs_artifacts
class TestIngest:
    def test_valid_and_rejected_files(self, service, real_flows, tmp_path):
        import ingest_dir
        df, feats = real_flows
        inbox = tmp_path / "inbox"
        inbox.mkdir()
        df.to_csv(inbox / "good.csv", index=False)
        (inbox / "bad.csv").write_text("x,y\n1,2\n")
        import os
        for f in inbox.iterdir():
            os.utime(f, (0, 0))   # pretend the exporter finished writing long ago
        ingest_dir.run(service, tmp_path, once=True, interval=0)
        assert list((tmp_path / "processed").glob("*_good.csv"))
        assert list((tmp_path / "rejected").glob("*_bad.csv"))
        assert list((tmp_path / "rejected").glob("*_bad.csv.reason.txt"))
        assert not list(inbox.iterdir())
        assert sum(service.store.stats()["by_severity"].values()) > 0


@needs_artifacts
class TestAPI:
    KEY = "test-key-123"

    @pytest.fixture
    def client(self, service, tmp_path):
        from fastapi.testclient import TestClient
        from api.main import create_app
        app = create_app(lambda: service, api_keys=(self.KEY,), rate_limit_per_min=1000,
                         audit_path=tmp_path / "audit.log", max_body_bytes=5_000_000)
        with TestClient(app) as c:
            c.audit = tmp_path / "audit.log"
            yield c

    H = {"X-API-Key": KEY}

    def test_probes_open_others_locked(self, client):
        assert client.get("/healthz").status_code == 200
        assert client.get("/readyz").status_code == 200
        assert client.get("/v1/policies").status_code == 401
        assert client.get("/v1/policies", headers={"X-API-Key": "wrong"}).status_code == 401
        assert client.get("/metrics").status_code == 401
        assert client.get("/v1/policies", headers={"Authorization": f"Bearer {self.KEY}"}).status_code == 200

    def test_score_json_and_alert_workflow(self, client, real_flows):
        df, feats = real_flows
        flows = json.loads(df[feats].head(60).to_json(orient="records"))
        r = client.post("/v1/score", json={"flows": flows}, headers=self.H)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["summary"]["flows"] == 60 and len(body["results"]) == 60
        alert = next((x for x in body["results"] if "alert_id" in x), None)
        if alert is None:
            flows = json.loads(df[df["Label"] != "BENIGN"][feats].head(60).to_json(orient="records"))
            body = client.post("/v1/score", json={"flows": flows}, headers=self.H).json()
            alert = next(x for x in body["results"] if "alert_id" in x)
        aid = alert["alert_id"]
        assert client.post(f"/v1/alerts/{aid}/status", json={"status": "confirmed"}, headers=self.H).status_code == 200
        assert client.post(f"/v1/alerts/{aid}/status", json={"status": "x"}, headers=self.H).status_code == 400
        assert client.get(f"/v1/alerts/{aid}", headers=self.H).json()["status"] == "confirmed"
        assert "features_json" not in client.get(f"/v1/alerts/{aid}", headers=self.H).json()
        assert client.get("/v1/feedback/export", headers=self.H).text.count("\n") >= 2
        assert client.get("/v1/alerts?status=bogus", headers=self.H).status_code == 400

    def test_bad_inputs(self, client, real_flows):
        _, feats = real_flows
        assert client.post("/v1/score", json={"flows": [{"nope": 1}]}, headers=self.H).status_code == 422
        assert client.post("/v1/score", json={"flows": []}, headers=self.H).status_code == 422
        flow = {f: 0.0 for f in feats}
        assert client.post("/v1/score", json={"flows": [flow], "policy": "zzz"}, headers=self.H).status_code == 400

    def test_csv_upload_and_body_limit(self, client, real_flows):
        df, feats = real_flows
        csv = df[feats].head(30).to_csv(index=False).encode()
        r = client.post("/v1/score/csv", files={"file": ("../../evil.csv", csv, "text/csv")}, headers=self.H)
        assert r.status_code == 200 and r.json()["summary"]["flows"] == 30
        big = b"a" * 6_000_000
        assert client.post("/v1/score/csv", files={"file": ("b.csv", big)}, headers=self.H).status_code == 413

    def test_metrics_and_audit_never_log_key(self, client):
        client.get("/v1/policies", headers=self.H)
        assert "ids_http_requests_total" in client.get("/metrics", headers=self.H).text
        log = client.audit.read_text()
        assert self.KEY not in log and '"status": 200' in log

    def test_rate_limit(self, service, tmp_path):
        from fastapi.testclient import TestClient
        from api.main import create_app
        app = create_app(lambda: service, api_keys=("k",), rate_limit_per_min=3, audit_path=None)
        with TestClient(app) as c:
            codes = [c.get("/v1/policies", headers={"X-API-Key": "k"}).status_code for _ in range(5)]
        assert codes[:3] == [200] * 3 and codes[3] == 429

    def test_refuses_to_start_without_auth(self, service):
        from fastapi.testclient import TestClient
        from api.main import create_app
        app = create_app(lambda: service, api_keys=(), allow_anon=False, audit_path=None)
        with pytest.raises(RuntimeError):
            with TestClient(app):
                pass
