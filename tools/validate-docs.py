#!/usr/bin/env python3
"""Validate the WinShow design documents against their own machine-readable contract.

This is the verification step for the documentation phase. There is no code to run yet, so
what gets checked is the contract itself:

  1. Every JSON Schema is itself a valid JSON Schema.
  2. Every message in docs/examples/transcript-*.jsonl validates against the WSAP/1 message
     schema.
  3. Event sequence numbers are gapless per correlation, and exec.exit is the last event for
     its correlation.
  4. Every example policy validates against the policy schema.
  5. Every operation and error code named in the documents exists in the schemas, and vice
     versa -- no drift between prose and contract.

Usage:
    python3 tools/validate-docs.py [--verbose]

Exit code is 0 when everything passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:  # pragma: no cover
    sys.exit("This script needs 'jsonschema'. Install it with: pip install jsonschema")

REPO = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO / "docs" / "schemas"
EXAMPLE_DIR = REPO / "docs" / "examples"
DOC_DIR = REPO / "docs"

failures: list[str] = []
checks_run = 0


def fail(message: str) -> None:
    failures.append(message)


def check(label: str, condition: bool, detail: str = "") -> None:
    global checks_run
    checks_run += 1
    if not condition:
        fail(f"{label}{': ' + detail if detail else ''}")


# --------------------------------------------------------------------------- schemas


def load_registry() -> tuple[Registry, dict[str, dict]]:
    """Load every schema in docs/schemas into a referencing Registry keyed by its $id."""
    registry = Registry()
    schemas: dict[str, dict] = {}
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"{path.name} is not valid JSON: {exc}")
            continue
        schemas[path.name] = doc
        schema_id = doc.get("$id")
        if not schema_id:
            fail(f"{path.name} has no $id, so it cannot be referenced")
            continue
        registry = registry.with_resource(schema_id, Resource.from_contents(doc))
    return registry, schemas


def check_schemas_are_valid(schemas: dict[str, dict]) -> None:
    for name, doc in schemas.items():
        try:
            Draft202012Validator.check_schema(doc)
            check(f"schema {name} is a valid JSON Schema", True)
        except Exception as exc:  # noqa: BLE001 - report whatever the library says
            check(f"schema {name} is a valid JSON Schema", False, str(exc))


# --------------------------------------------------------------------------- transcripts

COMMENT = re.compile(r"^\s*//")


def read_transcript(path: Path) -> list[tuple[int, dict]]:
    """Return (line number, message) for every non-comment, non-blank line."""
    messages: list[tuple[int, dict]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip() or COMMENT.match(raw):
            continue
        try:
            messages.append((lineno, json.loads(raw)))
        except json.JSONDecodeError as exc:
            fail(f"{path.name}:{lineno} is not valid JSON: {exc}")
    return messages


def event_group(message: dict) -> str:
    """Events for one correlation live in two independent sequence spaces.

    exec.ack travels server to agent and is numbered by the server; every other event
    travels agent to server and is numbered by the agent. Section 5.3 of the protocol makes
    them independent, so they must be checked independently.
    """
    return "server" if message.get("op") == "exec.ack" else "agent"


def check_transcript(path: Path, validator: Draft202012Validator) -> None:
    messages = read_transcript(path)
    check(f"{path.name} contains messages", bool(messages), "file has no message lines")

    sequences: dict[tuple[str, str], list[tuple[int, dict]]] = {}

    for lineno, message in messages:
        errors = sorted(validator.iter_errors(message), key=lambda e: list(e.absolute_path))
        if errors:
            first = errors[0]
            where = "/".join(str(p) for p in first.absolute_path) or "(root)"
            check(
                f"{path.name}:{lineno} validates",
                False,
                f"at {where}: {first.message}",
            )
        else:
            check(f"{path.name}:{lineno} validates", True)

        if message.get("t") == "evt":
            key = (message.get("corr", "?"), event_group(message))
            sequences.setdefault(key, []).append((lineno, message))

    for (corr, group), events in sequences.items():
        seqs = [m.get("seq") for _, m in events]
        expected = list(range(len(seqs)))
        check(
            f"{path.name} seq is gapless for corr={corr} ({group} side)",
            seqs == expected,
            f"got {seqs}, expected {expected}",
        )

        exits = [i for i, (_, m) in enumerate(events) if m.get("op") == "exec.exit"]
        if exits:
            check(
                f"{path.name} exec.exit is the last event for corr={corr}",
                exits == [len(events) - 1],
                f"exec.exit at index {exits}, but there are {len(events)} events",
            )


# --------------------------------------------------------------------------- policies


def check_policies(registry: Registry, schemas: dict[str, dict]) -> None:
    policy_schema = schemas.get("policy-v1.schema.json")
    if policy_schema is None:
        fail("policy-v1.schema.json is missing")
        return
    validator = Draft202012Validator(policy_schema, registry=registry)

    policies = sorted(EXAMPLE_DIR.glob("policy.*.toml"))
    check("example policies exist", bool(policies), "no policy.*.toml found")

    for path in policies:
        try:
            doc = tomllib.loads(path.read_text(encoding="utf-8"))
        except tomllib.TOMLDecodeError as exc:
            check(f"{path.name} parses as TOML", False, str(exc))
            continue
        check(f"{path.name} parses as TOML", True)

        errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
        if errors:
            first = errors[0]
            where = "/".join(str(p) for p in first.absolute_path) or "(root)"
            check(f"{path.name} validates", False, f"at {where}: {first.message}")
        else:
            check(f"{path.name} validates", True)


# --------------------------------------------------------------------------- consistency


def check_identifier_consistency(schemas: dict[str, dict]) -> None:
    """Prose and schema must name the same things.

    Drift here is the classic way a specification stops being implementable: the document
    says POLICY_DENIED, the schema says POLICY_REFUSED, and an implementer picks whichever
    they read last.
    """
    errors_schema = schemas.get("wsap-v1-errors.schema.json", {})
    messages_schema = schemas.get("wsap-v1-messages.schema.json", {})

    schema_codes = set(
        errors_schema.get("$defs", {}).get("errorCode", {}).get("enum", [])
    )
    check("error code enum is non-empty", bool(schema_codes))

    protocol = (DOC_DIR / "03-agent-protocol.md").read_text(encoding="utf-8")

    # Codes are documented as the first cell of a row in the section 7.2 table. Scoping to
    # that shape avoids sweeping up unrelated SCREAMING_SNAKE tokens such as PATH or COM1,
    # which are Windows names rather than error codes.
    documented = set(re.findall(r"^\| `([A-Z][A-Z0-9_]{3,})` \|", protocol, re.MULTILINE))

    # Server-originated codes never appear on the wire; they are defined for MCP clients in
    # 05-mcp-tool-surface.md and are named in a prose paragraph here.
    server_only = {
        "AGENT_UNAVAILABLE",
        "AGENT_DISCONNECTED",
        "AGENT_SUPERSEDED",
        "AGENT_TIMEOUT",
        "AGENT_PROTOCOL_ERROR",
    }
    for code in sorted(server_only):
        check(
            f"server-only code {code} is named in 03-agent-protocol.md",
            f"`{code}`" in protocol,
            "not mentioned",
        )

    undocumented = schema_codes - documented
    check(
        "every schema error code appears in the 03-agent-protocol.md code table",
        not undocumented,
        f"missing from prose: {sorted(undocumented)}",
    )

    unschematised = documented - schema_codes - server_only
    check(
        "every error code in the prose table exists in the schema",
        not unschematised,
        f"missing from schema: {sorted(unschematised)}",
    )

    # Every operation with a payload schema should appear in the protocol document, and every
    # operation named in a transcript should have a payload schema.
    schema_ops = {
        key.rsplit(".", 1)[0]
        for key in messages_schema.get("$defs", {})
        if key.endswith((".req", ".res", ".evt"))
    }
    for op in sorted(schema_ops):
        check(
            f"operation {op} is documented in 03-agent-protocol.md",
            f"`{op}`" in protocol,
            "not mentioned in the protocol document",
        )

    transcript_ops = set()
    for path in sorted(EXAMPLE_DIR.glob("transcript-*.jsonl")):
        for _, message in read_transcript(path):
            if "op" in message:
                transcript_ops.add(message["op"])
    missing = transcript_ops - schema_ops
    check(
        "every operation used in a transcript has a payload schema",
        not missing,
        f"no schema for: {sorted(missing)}",
    )


def check_cross_references() -> None:
    """Relative Markdown links inside docs/ must resolve to files that exist."""
    link = re.compile(r"\[[^\]]+\]\((?!https?://)([^)#]+)(?:#[^)]*)?\)")
    for path in sorted(DOC_DIR.rglob("*.md")):
        for target in link.findall(path.read_text(encoding="utf-8")):
            resolved = (path.parent / target).resolve()
            check(
                f"{path.relative_to(REPO)} link -> {target}",
                resolved.exists(),
                "target does not exist",
            )
    readme = REPO / "README.md"
    if readme.exists():
        for target in link.findall(readme.read_text(encoding="utf-8")):
            resolved = (readme.parent / target).resolve()
            check(f"README.md link -> {target}", resolved.exists(), "target does not exist")


# --------------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true", help="list every check performed")
    args = parser.parse_args()

    registry, schemas = load_registry()
    check_schemas_are_valid(schemas)

    messages_schema = schemas.get("wsap-v1-messages.schema.json")
    if messages_schema is None:
        fail("wsap-v1-messages.schema.json is missing")
    else:
        validator = Draft202012Validator(messages_schema, registry=registry)
        transcripts = sorted(EXAMPLE_DIR.glob("transcript-*.jsonl"))
        check("transcripts exist", bool(transcripts), "no transcript-*.jsonl found")
        for path in transcripts:
            check_transcript(path, validator)

    check_policies(registry, schemas)
    check_identifier_consistency(schemas)
    check_cross_references()

    print(f"ran {checks_run} checks")
    if failures:
        print(f"\n{len(failures)} FAILED:\n")
        for message in failures:
            print(f"  - {message}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
