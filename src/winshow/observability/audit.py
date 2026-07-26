"""The server-side audit trail.

``docs/02-architecture.md`` §9.2: every execution produces an append-only record **before
dispatch** and **after completion**. It is written on the server, which knows which MCP
client asked, and independently on the agent, which is the authority and whose copy
survives a compromised server. This module is only the server's half.

The field names are fixed by that section and are camelCase to match the agent's copy —
the two are meant to be greppable together.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from winshow.observability.logging import get_logger

__all__ = ["AuditLog"]

log = get_logger(__name__)


def _now() -> str:
    moment = datetime.now(UTC)
    return f"{moment:%Y-%m-%dT%H:%M:%S}.{moment.microsecond // 1000:03d}Z"


class AuditLog:
    """Append-only JSONL, or the structured log when no file is configured.

    Falling back to the structured log is the right default for a container, whose stdout
    is already collected somewhere durable; a file is for deployments that want the trail
    on a volume of their own.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, record: dict[str, Any]) -> None:
        """Emit one record.

        A failing audit write is logged and swallowed. Losing a tool call because the
        audit disk filled would be a worse outcome than the missing record, and the
        agent keeps its own independent copy — which is the authoritative one anyway.
        """
        try:
            line = json.dumps(record, default=str, ensure_ascii=False)
            if self.path is None:
                log.info("audit", extra={"event": "audit", **record})
                return
            with self._lock, self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
        except Exception:
            log.warning("audit.write_failed", extra={"event": "audit.write_failed"}, exc_info=True)

    def exec_dispatch(
        self,
        *,
        request_id: str,
        agent_id: str,
        hostname: str | None,
        mcp_client: dict[str, Any] | None,
        principal: str | None,
        argv: list[str] | None,
        shell: str,
        cwd: str | None,
        env_overlay_keys: list[str],
        timeout_ms: int | None,
    ) -> None:
        """Record an execution **before** it is sent to the agent.

        Written before dispatch precisely so that a command that never returns — because
        the agent died, or the host was powered off mid-run — still leaves a record that
        it was asked for.
        """
        self._write(
            {
                "ts": _now(),
                "kind": "exec.audit",
                "phase": "dispatch",
                "requestId": request_id,
                "agentId": agent_id,
                "hostname": hostname,
                "mcpClient": mcp_client,
                "principal": principal,
                "argv": argv,
                "shell": shell,
                "cwd": cwd,
                # The NAMES of overlaid environment variables, never their values: an
                # overlay is exactly where a caller would put a credential.
                "envOverlayKeys": env_overlay_keys,
                "timeoutMs": timeout_ms,
                # The server never decides policy (NFR-4); the agent's own audit copy
                # carries the decision and the deciding rule.
                "policyDecision": "delegated",
            }
        )

    def exec_complete(
        self,
        *,
        request_id: str,
        pid: int | None,
        exit_code: int | None,
        exit_reason: str,
        duration_ms: int,
        stdout_bytes: int,
        stderr_bytes: int,
        truncated: bool,
    ) -> None:
        self._write(
            {
                "ts": _now(),
                "kind": "exec.audit",
                "phase": "complete",
                "requestId": request_id,
                "pid": pid,
                "exitCode": exit_code,
                "exitReason": exit_reason,
                "durationMs": duration_ms,
                "stdoutBytes": stdout_bytes,
                "stderrBytes": stderr_bytes,
                "truncated": truncated,
            }
        )

    def exec_denied(
        self,
        *,
        request_id: str,
        agent_id: str,
        argv: list[str] | None,
        shell: str,
        rule: str | None,
        reason: str | None,
        reason_source: str | None,
    ) -> None:
        """Record a policy denial.

        Kept distinct from a completion so that denials can be counted and read without
        filtering successful runs out of the way — they are the records an auditor is
        most likely to have come for.
        """
        self._write(
            {
                "ts": _now(),
                "kind": "exec.audit",
                "phase": "denied",
                "requestId": request_id,
                "agentId": agent_id,
                "argv": argv,
                "shell": shell,
                "policyDecision": "deny",
                "policyRule": rule,
                "reason": reason,
                "reasonSource": reason_source,
            }
        )
