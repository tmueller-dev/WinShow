"""The envelope codec and the error taxonomy.

These are the rules an agent implementer reads §2 and §7 to learn, so they are tested
against the wording of the specification rather than against the implementation.
"""

from __future__ import annotations

import json

import pytest

from winshow.errors import (
    ErrorClass,
    ServerErrorCode,
    WinShowError,
    WireError,
    WireErrorCode,
    classify,
    is_retryable,
)
from winshow.wire.envelope import (
    Envelope,
    FrameTooLarge,
    MessageType,
    decode_frame,
    encode_frame,
    now_rfc3339,
)


class TestEnvelope:
    def test_request_round_trips(self) -> None:
        original = Envelope.request("r-1", "fs.list", {"path": "D:\\Logs"})
        parsed = decode_frame(encode_frame(original))
        assert parsed.t is MessageType.REQ
        assert parsed.id == "r-1"
        assert parsed.op == "fs.list"
        assert parsed.p == {"path": "D:\\Logs"}

    def test_event_carries_corr_and_seq(self) -> None:
        parsed = decode_frame(encode_frame(Envelope.event("r-1", 3, "exec.output", {"data": "x"})))
        assert parsed.corr == "r-1"
        assert parsed.seq == 3

    def test_error_uses_class_alias(self) -> None:
        # `class` is a Python keyword, so the field is aliased. It must still reach the
        # wire under its specified name.
        raw = encode_frame(
            Envelope.error("r-1", "fs.list", WireError.of(WireErrorCode.POLICY_DENIED, "no"))
        )
        assert json.loads(raw)["e"]["class"] == "policy"

    @pytest.mark.parametrize(
        "frame",
        [
            '{"w":2,"t":"req","id":"x","op":"a","p":{}}',  # unknown wire version
            '{"w":1,"t":"evt","op":"x","p":{}}',  # evt without corr/seq
            '{"w":1,"t":"req","id":"x","op":"a"}',  # req without p
            '{"w":1,"t":"res","op":"a","p":{}}',  # res without id
            '{"w":1,"t":"err","id":"x","op":"a"}',  # err without e
            '{"w":1,"t":"nope","id":"x","op":"a","p":{}}',  # unknown type
            "not json at all",
            "[1,2,3]",
        ],
    )
    def test_structural_violations_are_rejected(self, frame: str) -> None:
        with pytest.raises(WinShowError) as caught:
            decode_frame(frame)
        assert caught.value.code == WireErrorCode.MALFORMED_MESSAGE

    def test_unknown_fields_are_tolerated(self) -> None:
        # §11.1 rule 1: unknown fields at any depth are ignored, never an error. This is
        # what lets a v1 server keep working against a newer v1 agent.
        parsed = decode_frame(
            '{"w":1,"t":"req","id":"x","op":"fs.list","p":{"path":"C:\\\\","futureField":9},'
            '"somethingNew":true}'
        )
        assert parsed.op == "fs.list"
        assert parsed.p is not None
        assert parsed.p["futureField"] == 9

    def test_identifier_charset_is_enforced(self) -> None:
        with pytest.raises(WinShowError) as caught:
            decode_frame('{"w":1,"t":"req","id":"has space","op":"a","p":{}}')
        assert caught.value.code == WireErrorCode.MALFORMED_MESSAGE

    def test_oversized_frame_is_rejected_in_both_directions(self) -> None:
        big = Envelope.request("r-1", "fs.read", {"blob": "x" * 5000})
        with pytest.raises(FrameTooLarge):
            encode_frame(big, max_frame_bytes=1024)
        with pytest.raises(FrameTooLarge):
            decode_frame(encode_frame(big), max_frame_bytes=1024)

    def test_absent_optionals_do_not_appear_on_the_wire(self) -> None:
        raw = json.loads(encode_frame(Envelope.request("r-1", "fs.list", {})))
        assert "corr" not in raw
        assert "seq" not in raw
        assert "e" not in raw

    def test_timestamp_shape(self) -> None:
        stamp = now_rfc3339()
        assert stamp.endswith("Z")
        assert len(stamp) == len("2026-07-26T18:14:03.211Z")


class TestErrorTaxonomy:
    def test_policy_denied_is_never_retryable(self) -> None:
        # It will not become an allow by trying again, and marking it retryable invites a
        # model to churn through variants of a path until it gives up.
        assert is_retryable(WireErrorCode.POLICY_DENIED) is False
        assert classify(WireErrorCode.POLICY_DENIED) is ErrorClass.POLICY

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            (WireErrorCode.SHARING_VIOLATION, True),
            (WireErrorCode.IO_ERROR, True),
            (WireErrorCode.AGENT_BUSY, True),
            (WireErrorCode.TIMEOUT, True),
            (WireErrorCode.RESOURCE_EXHAUSTED, True),
            (WireErrorCode.NOT_FOUND, False),
            (WireErrorCode.ACCESS_DENIED, False),
            (WireErrorCode.CANCELLED, False),
            (WireErrorCode.INVALID_PATH, False),
            (ServerErrorCode.AGENT_UNAVAILABLE, True),
            (ServerErrorCode.AGENT_PROTOCOL_ERROR, False),
        ],
    )
    def test_retryability_matches_the_code_table(self, code: str, expected: bool) -> None:
        assert is_retryable(code) is expected

    def test_unknown_code_is_internal_and_not_retryable(self) -> None:
        # §7.4: forward compatibility. A newer agent may send a code this build predates.
        assert classify("SOMETHING_ADDED_LATER") is ErrorClass.INTERNAL
        assert is_retryable("SOMETHING_ADDED_LATER") is False

    def test_access_denied_is_distinct_from_policy_denied(self) -> None:
        # One is Windows refusing, the other is WinShow refusing. They have different
        # fixes, which is precisely why the specification keeps them apart.
        assert classify(WireErrorCode.ACCESS_DENIED) is ErrorClass.OS
        assert classify(WireErrorCode.POLICY_DENIED) is ErrorClass.POLICY

    def test_of_populates_class_and_retryable_from_the_table(self) -> None:
        error = WireError.of(WireErrorCode.SHARING_VIOLATION, "locked")
        assert error.cls is ErrorClass.OS
        assert error.retryable is True
