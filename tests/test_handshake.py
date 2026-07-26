"""The `/agent` handshake, driven over a real ASGI transport.

The test acts as the agent, because that is the direction the connection runs: the
Windows host dials out. Everything here is §1 (transport and authentication) and §3.1
(the handshake) of the protocol.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient, WebSocketDenialResponse, WebSocketDisconnect

from tests.conftest import AGENT_TOKEN
from tests.fake_agent import make_hello
from winshow.app import create_app
from winshow.config import Settings
from winshow.transport.agent_ws import SUBPROTOCOL


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client


def _headers(token: str = AGENT_TOKEN, agent_id: str = "WS-TEST-01") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-WinShow-Agent-Id": agent_id,
        "X-WinShow-Agent-Version": "0.0.1",
    }


class TestAuthentication:
    def test_missing_token_is_rejected_before_the_upgrade(self, client: TestClient) -> None:
        # §1.4 and ADR 0004: rejecting after the upgrade would hand an unauthenticated
        # peer a socket, which is a free denial of service.
        with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
            "/agent",
            subprotocols=[SUBPROTOCOL],
            headers={"X-WinShow-Agent-Id": "WS-TEST-01"},
        ):
            pass
        assert caught.value.status_code == 401
        assert caught.value.headers["WWW-Authenticate"] == "Bearer"

    def test_wrong_token_is_rejected(self, client: TestClient) -> None:
        with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers(token="w" * 40)
        ):
            pass
        assert caught.value.status_code == 401

    def test_token_never_appears_in_the_response(self, client: TestClient) -> None:
        # NFR-12: the agent's token appears in no log and no response at any level.
        with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers(token="s" * 40)
        ):
            pass
        assert "s" * 40 not in caught.value.text

    def test_missing_subprotocol_is_rejected(self, client: TestClient) -> None:
        # §1.2: an endpoint that does not speak winshow.v1 is not a WinShow server.
        with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
            "/agent", headers=_headers()
        ):
            pass
        assert caught.value.status_code == 400

    def test_malformed_agent_id_is_rejected(self, client: TestClient) -> None:
        with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
            "/agent",
            subprotocols=[SUBPROTOCOL],
            headers=_headers(agent_id="not a valid id!"),
        ):
            pass
        assert caught.value.status_code == 400

    def test_agent_id_not_on_the_allow_list_is_rejected(self, settings: Settings) -> None:
        pinned = settings.model_copy(update={"allowed_agent_ids": ["WS-PROD-01"]})
        with TestClient(create_app(pinned)) as client:
            with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
                    "/agent", subprotocols=[SUBPROTOCOL], headers=_headers(agent_id="WS-OTHER")
                ):
                pass
            assert caught.value.status_code == 403

    def test_repeated_failures_are_rate_limited(self, client: TestClient) -> None:
        # §1.4: five failures from one source in 60 seconds, then 429 with Retry-After.
        statuses = []
        for _ in range(7):
            with pytest.raises(WebSocketDenialResponse) as caught, client.websocket_connect(
                    "/agent", subprotocols=[SUBPROTOCOL], headers=_headers(token="x" * 40)
                ):
                pass
            statuses.append(caught.value.status_code)
        assert 429 in statuses
        assert statuses[-1] == 429


class TestHandshake:
    def test_successful_hello_negotiates_and_turns_readyz_green(
        self, client: TestClient
    ) -> None:
        assert client.get("/readyz").status_code == 503

        with client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers()
        ) as ws:
            ws.send_text(
                json.dumps({"w": 1, "t": "req", "id": "h-1", "op": "session.hello",
                            "p": make_hello()})
            )
            response = json.loads(ws.receive_text())
            assert response["t"] == "res"
            assert response["op"] == "session.hello"
            payload = response["p"]
            assert payload["wireVersion"] == 1
            assert payload["sessionId"].startswith("s-")
            # Each negotiated limit is the minimum of the two offers.
            assert payload["maxFrameBytes"] == 1_048_576
            # §11.2 rule 5: only operations the agent advertised come back enabled.
            assert set(payload["enabledOps"]) == {
                "fs.list", "fs.stat", "fs.read", "fs.glob", "fs.grep", "exec.start",
            }

            assert client.get("/readyz").status_code == 200
            assert client.get("/readyz").json()["agent_id"] == "WS-TEST-01"

        # The slot is released when the socket goes away.
        assert client.get("/readyz").status_code == 503

    def test_capabilities_are_intersected_not_trusted(self, client: TestClient) -> None:
        # An agent advertising something this build does not know about must not have it
        # echoed back as enabled.
        with client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers()
        ) as ws:
            ws.send_text(
                json.dumps(
                    {"w": 1, "t": "req", "id": "h-1", "op": "session.hello",
                     "p": make_hello(capabilities=["fs.list", "fs.telepathy"])}
                )
            )
            payload = json.loads(ws.receive_text())["p"]
            assert payload["enabledOps"] == ["fs.list"]

    def test_incompatible_wire_version_is_refused(self, client: TestClient) -> None:
        # §3.1: no intersection means err INCOMPATIBLE_VERSION and close 4004.
        with client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers()
        ) as ws:
            ws.send_text(
                json.dumps(
                    {"w": 1, "t": "req", "id": "h-1", "op": "session.hello",
                     "p": make_hello(wire_versions=[7, 9])}
                )
            )
            message = json.loads(ws.receive_text())
            assert message["t"] == "err"
            assert message["e"]["code"] == "INCOMPATIBLE_VERSION"

    def test_agent_id_must_match_the_header(self, client: TestClient) -> None:
        # The header and the handshake are two statements of the same fact; a mismatch
        # means one of them is not to be trusted.
        with client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers(agent_id="WS-TEST-01")
        ) as ws:
            ws.send_text(
                json.dumps(
                    {"w": 1, "t": "req", "id": "h-1", "op": "session.hello",
                     "p": make_hello(agent_id="WS-SOMETHING-ELSE")}
                )
            )
            message = json.loads(ws.receive_text())
            assert message["t"] == "err"
            assert message["e"]["code"] == "INVALID_ARGUMENT"

    def test_first_message_must_be_hello(self, client: TestClient) -> None:
        # §3.1: the agent speaks first, and what it says is session.hello. Anything else
        # means the peer is not following the handshake, so the socket closes.
        with client.websocket_connect(
            "/agent", subprotocols=[SUBPROTOCOL], headers=_headers()
        ) as ws:
            ws.send_text(json.dumps({"w": 1, "t": "req", "id": "x", "op": "fs.list", "p": {}}))
            with pytest.raises(WebSocketDisconnect):
                ws.receive_text()

    def test_hello_timeout_closes_the_socket(self, settings: Settings) -> None:
        # §1.8, code 4008. A peer that upgrades and then says nothing must not hold the
        # socket open indefinitely.
        impatient = settings.model_copy(update={"hello_timeout_ms": 50})
        with (
            TestClient(create_app(impatient)) as client,
            client.websocket_connect(
                "/agent", subprotocols=[SUBPROTOCOL], headers=_headers()
            ) as ws,
        ):
            with pytest.raises(WebSocketDisconnect) as caught:
                ws.receive_text()
            assert caught.value.code == 4008


class TestHealthEndpoints:
    def test_healthz_is_green_without_an_agent(self, client: TestClient) -> None:
        # Liveness answers "should this process be restarted". Restarting the server
        # because the Windows host rebooted would be exactly wrong.
        body = client.get("/healthz")
        assert body.status_code == 200
        assert body.json()["status"] == "ok"

    def test_metrics_are_not_on_the_public_listener(self, client: TestClient) -> None:
        # The metric set names the agent, the host and the denial counts.
        response = client.get("/metrics")
        assert response.status_code == 404
        assert "admin listener" in response.text


class TestMcpEndpoint:
    def test_tools_are_listed(self, client: TestClient) -> None:
        response = client.post(
            "/mcp/",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Origin": "https://client.example",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1"},
                },
            },
        )
        assert response.status_code == 200

    def test_disallowed_origin_is_refused(self, client: TestClient) -> None:
        # §6 of the security document: the server validates Origin and returns 403 on a
        # mismatch, so a browser cannot be used as a confused deputy.
        response = client.post(
            "/mcp/",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Origin": "https://evil.example",
            },
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert response.status_code == 403
