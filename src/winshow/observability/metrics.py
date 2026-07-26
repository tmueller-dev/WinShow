"""Prometheus metrics.

The exposed set is exactly the one named in ``docs/02-architecture.md`` §9.3 and
``docs/07-operations.md`` §7.1 — no more, because a metric nobody acts on is a metric
that costs cardinality and attention for nothing.

These are served on a **separate admin bind address** (127.0.0.1:9090 by default), never
through the public listener: the set names the agent, the host and the denial counts, and
none of that belongs on the internet.
"""

from __future__ import annotations

from typing import Any

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from prometheus_client.exposition import CONTENT_TYPE_LATEST

__all__ = [
    "REGISTRY",
    "metrics_app",
    "record_bytes",
    "record_denial",
    "record_reconnect",
    "record_request",
    "record_rtt",
    "record_truncation",
    "set_agent_connected",
    "set_exec_running",
    "set_inflight",
]

#: A private registry rather than the global default, so that importing the module twice
#: or resetting it in a test cannot raise a duplicate-registration error.
REGISTRY = CollectorRegistry()

AGENT_CONNECTED = Gauge(
    "winshow_agent_connected",
    "1 when an agent is connected and past session.hello, 0 otherwise.",
    registry=REGISTRY,
)
AGENT_RECONNECTS = Counter(
    "winshow_agent_reconnects_total",
    "Agent connection establishments. The derivative is what matters, not the value.",
    registry=REGISTRY,
)
AGENT_RTT = Histogram(
    "winshow_agent_rtt_seconds",
    "Round-trip time of session.ping, measured from the heartbeat.",
    registry=REGISTRY,
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
REQUESTS = Counter(
    "winshow_requests_total",
    "Wire operations dispatched, by operation and outcome.",
    labelnames=("op", "outcome"),
    registry=REGISTRY,
)
REQUEST_DURATION = Histogram(
    "winshow_request_duration_seconds",
    "End-to-end duration per operation, from the MCP call to the agent's response.",
    labelnames=("op",),
    registry=REGISTRY,
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0, 60.0, 300.0),
)
POLICY_DENIALS = Counter(
    "winshow_policy_denials_total",
    "Policy denials by operation and deciding rule. The one to alert on.",
    labelnames=("op", "rule"),
    registry=REGISTRY,
)
INFLIGHT = Gauge(
    "winshow_inflight_requests",
    "Requests currently outstanding against the agent.",
    registry=REGISTRY,
)
EXEC_RUNNING = Gauge(
    "winshow_exec_running",
    "Child processes the agent currently reports as running.",
    registry=REGISTRY,
)
BYTES_STREAMED = Counter(
    "winshow_bytes_streamed_total",
    "Bytes across the agent link, by direction.",
    labelnames=("direction",),
    registry=REGISTRY,
)
TRUNCATIONS = Counter(
    "winshow_truncations_total",
    "Results truncated, by reason. Persistent truncation means the caps need revisiting.",
    labelnames=("reason",),
    registry=REGISTRY,
)


# Thin helpers so no call site has to know a label name. Getting a label wrong at one of
# a dozen call sites produces a silently separate time series, which is the kind of bug
# that is only noticed when a dashboard is needed in an incident.


def set_agent_connected(connected: bool) -> None:
    AGENT_CONNECTED.set(1 if connected else 0)


def record_reconnect() -> None:
    AGENT_RECONNECTS.inc()


def record_rtt(seconds: float) -> None:
    AGENT_RTT.observe(seconds)


def record_request(op: str, outcome: str, duration_seconds: float) -> None:
    REQUESTS.labels(op=op, outcome=outcome).inc()
    REQUEST_DURATION.labels(op=op).observe(duration_seconds)


def record_denial(op: str, rule: str) -> None:
    POLICY_DENIALS.labels(op=op, rule=rule).inc()


def set_inflight(count: int) -> None:
    INFLIGHT.set(count)


def set_exec_running(count: int) -> None:
    EXEC_RUNNING.set(count)


def record_bytes(direction: str, count: int) -> None:
    BYTES_STREAMED.labels(direction=direction).inc(count)


def record_truncation(reason: str) -> None:
    TRUNCATIONS.labels(reason=reason).inc()


def metrics_app() -> Any:
    """A minimal ASGI app serving the Prometheus exposition.

    Written by hand rather than mounted from `prometheus_client` because it must be
    bound to its own listener, and pulling in the WSGI bridge for four lines of output
    would be the larger dependency.
    """

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        if scope.get("path", "/") not in ("/metrics", "/"):
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b"not found"})
            return
        body = generate_latest(REGISTRY)
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", CONTENT_TYPE_LATEST.encode()),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app
