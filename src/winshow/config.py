"""Server configuration.

Everything is an environment variable prefixed ``WINSHOW_``, because the server is
deployed as a container and a container's configuration surface should be one thing
rather than two. Operational guidance for these values is in ``docs/07-operations.md``
§1.2; the security reasoning behind the origin check and the token rules is in
``docs/06-security.md`` §6.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

__all__ = ["Settings", "get_settings"]

#: §1.7. The default frame cap, and the hard ceiling a deployment may raise it to.
DEFAULT_MAX_FRAME_BYTES = 1_048_576
CEILING_MAX_FRAME_BYTES = 8_388_608

#: §1.4. Shorter than this and the token cannot carry 32 bytes of CSPRNG output, which
#: is the one part of the entropy rule a peer can actually detect.
MIN_TOKEN_LENGTH = 32


def _split_csv(value: Any) -> Any:
    """Accept both a comma-separated string and a real list.

    Docker Compose, systemd unit files and Kubernetes manifests all hand over strings;
    a test or a Python caller hands over a list. Supporting both removes a class of
    "works locally, fails in the cluster" configuration bug.
    """
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    """Everything the server needs to run."""

    model_config = SettingsConfigDict(
        env_prefix="WINSHOW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- listeners ---------------------------------------------------------------

    host: str = "0.0.0.0"  # noqa: S104 — a container binds all interfaces by design
    port: int = 8080

    #: `/metrics` binds separately and defaults to loopback: the metric set names the
    #: agent, the host and the denial counts, and none of that belongs on the internet
    #: (§1.1). Set to an empty string to disable the admin listener entirely.
    admin_host: str = "127.0.0.1"
    admin_port: int = 9090
    metrics_enabled: bool = True

    #: The path the agent dials. Configurable because a reverse proxy may mount the
    #: application under a prefix.
    agent_path: str = "/agent"
    mcp_path: str = "/mcp"

    # -- agent link --------------------------------------------------------------

    #: The valid bearer tokens. §1.4 requires **two** to be simultaneously valid so a
    #: token can be rotated without downtime; more than two is allowed but means a
    #: rotation was left unfinished.
    agent_tokens: Annotated[list[str], Field(default_factory=list)]

    #: When non-empty, the `X-WinShow-Agent-Id` header must appear in this list. Q-5
    #: leans towards pinning from the start: it costs nothing and it is the multi-host
    #: extension point.
    allowed_agent_ids: Annotated[list[str], Field(default_factory=list)]

    #: §3.1 / NFR-8. The server pings on this cadence and declares the peer dead after
    #: `agent_dead_after_ms` of silence.
    heartbeat_interval_ms: int = 20_000
    agent_dead_after_ms: int = 60_000

    #: §3.1: no `session.hello` within this window closes the socket with 4008.
    hello_timeout_ms: int = 10_000

    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES

    #: §9.3. The server's side of the credit window; the effective value is the minimum
    #: of what each side offers.
    ack_window_chunks: int = 64
    ack_window_bytes: int = 4_194_304

    # -- request handling --------------------------------------------------------

    #: §8.1 of the architecture: a small grace period lets a call arriving during a
    #: two-second reconnection blip wait rather than fail. Default 0 — fail fast — with
    #: 3000 recommended for deployments that see flaky links.
    wait_for_agent_ms: int = 0

    #: §8.6. The server's timeout is a safety net set past the agent's own. If it ever
    #: fires the agent is misbehaving, and that is logged at WARN rather than hidden.
    server_timeout_margin_ms: int = 5_000

    #: Default deadline for operations that do not carry one of their own.
    default_request_timeout_ms: int = 60_000

    #: The per-request output buffer cap on the server side (§7.3 of the architecture).
    max_buffered_output_bytes: int = 4_194_304

    # -- MCP side ----------------------------------------------------------------

    #: §6 of the security document: the server MUST validate `Origin` on `/mcp` and
    #: return 403 on a mismatch. An empty list disables the check, which is only
    #: appropriate behind an authenticating proxy that does it instead.
    allowed_origins: Annotated[list[str], Field(default_factory=list)]

    #: DNS-rebinding protection in the MCP SDK's transport layer. Empty means any Host.
    allowed_hosts: Annotated[list[str], Field(default_factory=list)]

    # -- observability -----------------------------------------------------------

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "text"] = "json"

    #: Append-only server-side audit trail. Unset means audit records go to the
    #: structured log only, which is the right default for a container whose stdout is
    #: already collected.
    audit_file: Path | None = None

    _split = field_validator(
        "agent_tokens", "allowed_agent_ids", "allowed_origins", "allowed_hosts", mode="before"
    )(_split_csv)

    @field_validator("agent_tokens")
    @classmethod
    def _tokens_long_enough(cls, tokens: list[str]) -> list[str]:
        # §1.4: the server SHOULD refuse to start with a token shorter than 32
        # characters. Entropy is not observable in a string, but length is, and a short
        # token is the one failure of the rule that is detectable from here.
        short = [f"#{i + 1}" for i, tok in enumerate(tokens) if len(tok) < MIN_TOKEN_LENGTH]
        if short:
            raise ValueError(
                f"agent token(s) {', '.join(short)} are shorter than {MIN_TOKEN_LENGTH} characters. "
                "Generate one with: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        return tokens

    @field_validator("max_frame_bytes")
    @classmethod
    def _frame_within_ceiling(cls, value: int) -> int:
        if not 1024 <= value <= CEILING_MAX_FRAME_BYTES:
            raise ValueError(
                f"max_frame_bytes must be between 1024 and {CEILING_MAX_FRAME_BYTES} (§1.7)"
            )
        return value

    @model_validator(mode="after")
    def _timeouts_are_ordered(self) -> Settings:
        if self.agent_dead_after_ms <= self.heartbeat_interval_ms:
            raise ValueError(
                "agent_dead_after_ms must exceed heartbeat_interval_ms, otherwise a healthy "
                "agent is declared dead between two pings"
            )
        return self

    # -- helpers -----------------------------------------------------------------

    def token_is_valid(self, presented: str) -> bool:
        """Constant-time comparison against every configured token (§1.4).

        Every token is compared even after a match, so the time taken does not reveal
        which token matched or how many are configured.
        """
        matched = False
        for token in self.agent_tokens:
            if secrets.compare_digest(presented, token):
                matched = True
        return matched

    def agent_id_is_allowed(self, agent_id: str) -> bool:
        """An empty allow-list means any identifier; otherwise membership is required."""
        return not self.allowed_agent_ids or agent_id in self.allowed_agent_ids

    def origin_is_allowed(self, origin: str | None) -> bool:
        """Validate the `Origin` header of an `/mcp` request.

        A request with no `Origin` is accepted: non-browser MCP clients do not send one,
        and the header exists to stop a *browser* being used as a confused deputy.
        """
        if not self.allowed_origins or origin is None:
            return True
        return origin in self.allowed_origins


_settings: Settings | None = None


def get_settings(**overrides: Any) -> Settings:
    """Return the process-wide settings, constructing them on first use.

    Passing overrides always builds a fresh instance, which is what tests want and what
    a caller embedding the app in another process needs.
    """
    global _settings
    if overrides:
        return Settings(**overrides)
    if _settings is None:
        _settings = Settings()
    return _settings
