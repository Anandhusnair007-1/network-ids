"""
src/sinks.py
============
Alert export: push alerts to a SIEM / chat / ticketing system.

* ``SyslogCEFSink``  - ArcSight CEF over UDP syslog (Splunk, QRadar, Wazuh, Elastic all parse it).
* ``WebhookSink``    - JSON POST with an HMAC-SHA256 signature header the receiver can verify.

Destinations come from operator configuration only, never from request data, so callers of the
API cannot steer the server at internal hosts (SSRF). Sink failures are logged and counted but never
break scoring.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import socket
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("ids.sinks")

SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
CEF_SEVERITY = {"HIGH": 9, "MEDIUM": 6, "LOW": 3, "INFO": 0}


def _cef_escape(value: Any, extension: bool = False) -> str:
    text = str(value).replace("\\", "\\\\")
    text = text.replace("=", "\\=") if extension else text.replace("|", "\\|")
    return text.replace("\r", " ").replace("\n", " ")


def to_cef(alert: dict[str, Any]) -> str:
    """Format one alert as a CEF:0 line."""
    sev = str(alert.get("severity", "INFO"))
    ext = {
        "externalId": alert.get("alert_id", ""),
        "src": alert.get("src_ip") or "",
        "dst": alert.get("dst_ip") or "",
        "cs1Label": "classifier", "cs1": alert.get("rf_label", ""),
        "cn1Label": "anomalyScore", "cn1": f"{float(alert.get('anomaly_score', 0)):.4f}",
        "cn2Label": "classifierConfidence", "cn2": f"{float(alert.get('rf_confidence', 0)):.4f}",
    }
    ext_str = " ".join(f"{k}={_cef_escape(v, True)}" for k, v in ext.items() if v != "")
    return (
        f"CEF:0|NetworkIDS|HybridNIDS|1.0|{_cef_escape(alert.get('final_label', 'alert'))}|"
        f"{_cef_escape(alert.get('final_label', 'alert'))}|{CEF_SEVERITY.get(sev, 0)}|{ext_str}"
    )


class Sink:
    name = "sink"

    def send(self, alerts: list[dict[str, Any]]) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class SyslogCEFSink(Sink):
    name = "syslog"

    def __init__(self, host: str, port: int = 514, facility: int = 1) -> None:
        self.addr = (host, int(port))
        self.facility = facility

    def send(self, alerts: list[dict[str, Any]]) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for a in alerts:
                pri = self.facility * 8 + (2 if a.get("severity") == "HIGH" else 4)
                msg = f"<{pri}>{time.strftime('%b %d %H:%M:%S')} network-ids {to_cef(a)}"
                sock.sendto(msg.encode("utf-8", "replace")[:1024], self.addr)
        finally:
            sock.close()


class WebhookSink(Sink):
    name = "webhook"

    def __init__(self, url: str, secret: str = "", timeout: float = 5.0) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("Webhook URL must be http(s)://host/...")
        self.url, self.secret, self.timeout = url, secret.encode(), timeout

    def send(self, alerts: list[dict[str, Any]]) -> None:
        body = json.dumps({"source": "network-ids", "alerts": alerts}, default=str).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "network-ids/1.0"}
        if self.secret:
            headers["X-IDS-Signature"] = "sha256=" + hmac.new(self.secret, body, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")  # noqa: S310
        with urllib.request.urlopen(req, timeout=self.timeout):  # noqa: S310  # nosec B310 - scheme validated above
            pass


class SinkManager:
    """Fans alerts out to every configured sink, filtered by minimum severity."""

    def __init__(self, sinks: Iterable[Sink] = (), min_severity: str = "MEDIUM") -> None:
        self.sinks = list(sinks)
        self.min_rank = SEV_RANK.get(min_severity.upper(), 2)
        self.sent = 0
        self.failed = 0

    @classmethod
    def from_config(cls, webhook_url: str, webhook_secret: str, syslog_addr: str, min_severity: str) -> SinkManager:
        sinks: list[Sink] = []
        if webhook_url:
            sinks.append(WebhookSink(webhook_url, webhook_secret))
        if syslog_addr:
            host, _, port = syslog_addr.partition(":")
            sinks.append(SyslogCEFSink(host, int(port or 514)))
        return cls(sinks, min_severity)

    def dispatch(self, alerts: list[dict[str, Any]]) -> None:
        batch = [a for a in alerts if SEV_RANK.get(a.get("severity", "INFO"), 0) >= self.min_rank]
        if not batch:
            return
        for sink in self.sinks:
            try:
                sink.send(batch)
                self.sent += len(batch)
            except (OSError, urllib.error.URLError, ValueError) as exc:
                self.failed += len(batch)
                log.error("Alert sink %s failed: %s", sink.name, exc)
