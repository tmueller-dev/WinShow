"""Conformance against the documented wire transcripts and schemas.

`docs/examples/README.md` calls the transcripts "the test vectors for the Phase 2
conformance harness". This is that harness.

Two directions are checked, and both matter:

* **Consume.** Every message in every transcript must parse with our codec, and the
  sequences they document must satisfy our ordering checks. A vector our own server
  rejects means either the implementation or the specification is wrong.
* **Produce.** Every message the server *emits* must validate against
  ``docs/schemas/wsap-v1-messages.schema.json``. Without this, the server could drift
  from its own published contract and only a third-party agent would ever notice.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from tests.fake_agent import connected_session
from winshow.bridge.bridge import AgentBridge
from winshow.bridge.inflight import InflightRequest
from winshow.config import Settings
from winshow.errors import AgentProtocolError
from winshow.wire.envelope import Envelope, MessageType, decode_frame
from winshow.wire.messages import Op

DOCS = Path(__file__).resolve().parent.parent / "docs"
TRANSCRIPTS = sorted((DOCS / "examples").glob("transcript-*.jsonl"))


def _load_registry() -> tuple[Registry, dict[str, dict[str, Any]]]:
    """Index every schema by its `$id`.

    The schemas cross-reference each other by absolute URL — the envelope refers to the
    error schema that way — so validating one in isolation would try to fetch that URL
    over the network. Registering them locally is what `tools/validate-docs.py` does, and
    the harness has to match it or it is testing a different contract.
    """
    registry = Registry()
    by_name: dict[str, dict[str, Any]] = {}
    for path in sorted((DOCS / "schemas").glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        by_name[path.name] = document
        registry = registry.with_resource(document["$id"], Resource.from_contents(document))
    return registry, by_name


REGISTRY, SCHEMAS = _load_registry()
MESSAGE_SCHEMA = SCHEMAS["wsap-v1-messages.schema.json"]
ENVELOPE_SCHEMA = SCHEMAS["wsap-v1-envelope.schema.json"]
ERROR_SCHEMA = SCHEMAS["wsap-v1-errors.schema.json"]


def check(instance: Any, schema: dict[str, Any]) -> None:
    Draft202012Validator(schema, registry=REGISTRY).validate(instance)


def transcript_messages(path: Path) -> list[dict[str, Any]]:
    """Parse a transcript, dropping annotations.

    A line whose first two non-whitespace characters are `//` is commentary, not a
    message; blank lines are ignored.
    """
    messages = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        messages.append(json.loads(stripped))
    return messages


def _schema_key(message: dict[str, Any]) -> str | None:
    """Map a message onto its `$defs` entry, e.g. `fs.list.req`."""
    op = message.get("op")
    kind = message.get("t")
    if not op or kind == "err":
        return None
    suffix = {"req": "req", "res": "res", "evt": "evt"}.get(str(kind))
    if suffix is None:
        return None
    return f"{op}.{suffix}"


def validate_payload(message: dict[str, Any]) -> None:
    """Validate a message's payload against its schema, when one is defined."""
    key = _schema_key(message)
    if key is None or key not in MESSAGE_SCHEMA["$defs"]:
        return
    schema = dict(MESSAGE_SCHEMA["$defs"][key])
    schema["$defs"] = MESSAGE_SCHEMA["$defs"]
    check(message.get("p", {}), schema)


assert TRANSCRIPTS, "no transcripts found — the conformance vectors are missing"


class TestTranscriptsParse:
    @pytest.mark.parametrize("path", TRANSCRIPTS, ids=lambda p: p.name)
    def test_every_message_decodes(self, path: Path) -> None:
        messages = transcript_messages(path)
        assert messages, f"{path.name} contains no messages"
        for message in messages:
            envelope = decode_frame(json.dumps(message))
            assert envelope.w == 1

    @pytest.mark.parametrize("path", TRANSCRIPTS, ids=lambda p: p.name)
    def test_every_message_matches_the_envelope_schema(self, path: Path) -> None:
        for message in transcript_messages(path):
            check(message, ENVELOPE_SCHEMA)

    @pytest.mark.parametrize("path", TRANSCRIPTS, ids=lambda p: p.name)
    def test_every_payload_matches_its_operation_schema(self, path: Path) -> None:
        for message in transcript_messages(path):
            validate_payload(message)

    @pytest.mark.parametrize("path", TRANSCRIPTS, ids=lambda p: p.name)
    async def test_documented_sequences_pass_our_gap_check(self, path: Path) -> None:
        """The server's own ordering check must accept every documented sequence.

        `exec.ack` is excluded because it travels the other way and draws from an
        independent server-side sequence space (§8.2).

        Async so that a running loop exists: `InflightRequest` holds a future, and
        creating one without a loop picks up whatever state an earlier test left.
        """
        trackers: dict[str, InflightRequest] = {}
        for message in transcript_messages(path):
            if message.get("t") != "evt" or message.get("op") == Op.EXEC_ACK:
                continue
            corr = message["corr"]
            if corr not in trackers:
                trackers[corr] = InflightRequest(
                    id=corr,
                    op="test",
                    future=asyncio.get_running_loop().create_future(),
                    deadline=0.0,
                )
            trackers[corr].note_event_seq(message["seq"])

    @pytest.mark.parametrize("path", TRANSCRIPTS, ids=lambda p: p.name)
    def test_exec_exit_is_the_last_event_for_its_correlation(self, path: Path) -> None:
        seen_exit: set[str] = set()
        for message in transcript_messages(path):
            if message.get("t") != "evt":
                continue
            corr = message["corr"]
            if message.get("op") == Op.EXEC_ACK:
                continue
            assert corr not in seen_exit, (
                f"{path.name}: event {message.get('op')} follows exec.exit for {corr}"
            )
            if message.get("op") == Op.EXEC_EXIT:
                seen_exit.add(corr)


class TestGapDetectionRejectsABrokenVector:
    """The gap check must actually fail on a gap, not merely pass on good input."""

    async def test_a_missing_sequence_number_is_caught(self) -> None:
        tracker = InflightRequest(
            id="r-1",
            op="test",
            future=asyncio.get_running_loop().create_future(),
            deadline=0.0,
        )
        tracker.note_event_seq(0)
        tracker.note_event_seq(1)
        with pytest.raises(AgentProtocolError):
            tracker.note_event_seq(3)


class TestServerEmissionsAreValid:
    """Everything the server puts on the wire validates against the published schema."""

    async def test_hello_response_validates(self, settings: Settings) -> None:
        from starlette.testclient import TestClient

        from tests.conftest import AGENT_TOKEN
        from tests.fake_agent import make_hello
        from winshow.app import create_app
        from winshow.transport.agent_ws import SUBPROTOCOL

        with TestClient(create_app(settings)) as client, client.websocket_connect(
            "/agent",
            subprotocols=[SUBPROTOCOL],
            headers={
                "Authorization": f"Bearer {AGENT_TOKEN}",
                "X-WinShow-Agent-Id": "WS-TEST-01",
                "X-WinShow-Agent-Version": "0.0.1",
            },
        ) as ws:
            ws.send_text(
                json.dumps(
                    {"w": 1, "t": "req", "id": "h-1", "op": "session.hello", "p": make_hello()}
                )
            )
            response = json.loads(ws.receive_text())
            check(response, ENVELOPE_SCHEMA)
            validate_payload(response)

    async def test_requests_events_and_cancels_validate(self, settings: Settings) -> None:
        session, agent, _ws, serving = await connected_session(settings)
        bridge = AgentBridge(settings)
        await bridge.attach(session)
        agent.serve_exec(chunks=[("stdout", "a"), ("stdout", "b")])

        await bridge.call(Op.EXEC_START, {"argv": ["tasklist.exe"], "shell": "none"})
        await session.cancel("r-nonexistent", "client_cancelled")
        await session.say_goodbye("shutdown", "test over")

        # Frames are consumed by the harness asynchronously, so wait for the last one
        # rather than asserting on a race.
        assert await agent.wait_for(
            lambda: any(e.op == Op.SESSION_BYE for e in agent.received)
        ), "session.bye never arrived"
        assert agent.received, "the agent saw nothing"
        for envelope in agent.received:
            raw = json.loads(envelope.to_json())
            check(raw, ENVELOPE_SCHEMA)
            validate_payload(raw)

        # The specific ones worth naming, so a regression says which contract broke.
        kinds = {(e.t, e.op) for e in agent.received}
        assert (MessageType.REQ, Op.EXEC_START) in kinds
        assert (MessageType.EVT, Op.EXEC_ACK) in kinds
        assert (MessageType.REQ, Op.SESSION_CANCEL) in kinds
        assert (MessageType.EVT, Op.SESSION_BYE) in kinds

        await agent.stop()
        serving.cancel()
        await asyncio.gather(serving, return_exceptions=True)

    def test_error_envelopes_validate(self) -> None:
        from winshow.errors import WireError, WireErrorCode

        for code in (
            WireErrorCode.POLICY_DENIED,
            WireErrorCode.NOT_FOUND,
            WireErrorCode.AGENT_BUSY,
            WireErrorCode.INTERNAL_ERROR,
        ):
            envelope = Envelope.error("r-1", "fs.list", WireError.of(code, "message"))
            raw = json.loads(envelope.to_json())
            check(raw, ENVELOPE_SCHEMA)
            check(raw["e"], ERROR_SCHEMA)
