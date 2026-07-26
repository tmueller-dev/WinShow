"""Configuration, driven the way a deployment actually drives it.

Every test here goes through **environment variables** rather than constructing
`Settings(...)` in Python. That distinction is not academic: pydantic-settings treats a
list-valued field as complex and JSON-decodes it before any validator runs, so
`WINSHOW_AGENT_TOKENS=a,b` raised a `JSONDecodeError` at startup while every
Python-constructed test passed. The documented configuration form did not work at all,
and only an environment-driven test could see it.
"""

from __future__ import annotations

import secrets

import pytest
from pydantic import ValidationError

from winshow.config import Settings

TOKEN_A = secrets.token_urlsafe(32)
TOKEN_B = secrets.token_urlsafe(32)


class TestListsFromTheEnvironment:
    def test_comma_separated_tokens_parse(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", f"{TOKEN_A},{TOKEN_B}")
        settings = Settings()
        assert settings.agent_tokens == [TOKEN_A, TOKEN_B]

    def test_a_single_token_parses(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        assert Settings().agent_tokens == [TOKEN_A]

    def test_surrounding_whitespace_is_tolerated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A value pasted into a compose file or a unit file routinely carries spaces.
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", f" {TOKEN_A} , {TOKEN_B} ")
        assert Settings().agent_tokens == [TOKEN_A, TOKEN_B]

    def test_every_list_field_accepts_the_same_form(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        monkeypatch.setenv("WINSHOW_ALLOWED_ORIGINS", "https://a.example,https://b.example")
        monkeypatch.setenv("WINSHOW_ALLOWED_AGENT_IDS", "WS-PROD-01,WS-PROD-02")
        monkeypatch.setenv("WINSHOW_ALLOWED_HOSTS", "winshow.example.com")
        settings = Settings()
        assert settings.allowed_origins == ["https://a.example", "https://b.example"]
        assert settings.allowed_agent_ids == ["WS-PROD-01", "WS-PROD-02"]
        assert settings.allowed_hosts == ["winshow.example.com"]

    def test_empty_lists_are_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in (
            "WINSHOW_AGENT_TOKENS",
            "WINSHOW_ALLOWED_ORIGINS",
            "WINSHOW_ALLOWED_AGENT_IDS",
            "WINSHOW_ALLOWED_HOSTS",
        ):
            monkeypatch.delenv(name, raising=False)
        settings = Settings()
        assert settings.agent_tokens == []
        # NFR-15: the server starts and serves MCP with no agent configured or connected.
        # It simply cannot authenticate one, which is a legible failure rather than a
        # refusal to boot.
        assert settings.allowed_origins == []


class TestScalarsFromTheEnvironment:
    def test_numeric_and_boolean_settings_parse(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        monkeypatch.setenv("WINSHOW_PORT", "9999")
        monkeypatch.setenv("WINSHOW_WAIT_FOR_AGENT_MS", "3000")
        monkeypatch.setenv("WINSHOW_METRICS_ENABLED", "false")
        monkeypatch.setenv("WINSHOW_LOG_FORMAT", "text")
        settings = Settings()
        assert settings.port == 9999
        assert settings.wait_for_agent_ms == 3000
        assert settings.metrics_enabled is False
        assert settings.log_format == "text"


class TestValidation:
    def test_a_short_token_refuses_to_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # §1.4: entropy is not observable in a string, but length is, and a short token is
        # the one failure of the rule that is detectable from here.
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", "too-short")
        with pytest.raises(Exception) as caught:
            Settings()
        assert "32 characters" in str(caught.value)

    def test_a_frame_cap_above_the_ceiling_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        monkeypatch.setenv("WINSHOW_MAX_FRAME_BYTES", "99999999")
        with pytest.raises(ValidationError) as caught:
            Settings()
        assert "max_frame_bytes" in str(caught.value)

    def test_a_dead_peer_timer_inside_the_heartbeat_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Otherwise a perfectly healthy agent is declared dead between two pings.
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        monkeypatch.setenv("WINSHOW_HEARTBEAT_INTERVAL_MS", "60000")
        monkeypatch.setenv("WINSHOW_AGENT_DEAD_AFTER_MS", "20000")
        with pytest.raises(Exception) as caught:
            Settings()
        assert "declared dead" in str(caught.value)


class TestTokenComparison:
    def test_only_a_configured_token_matches(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", f"{TOKEN_A},{TOKEN_B}")
        settings = Settings()
        # Two valid at once is what makes rotation a no-downtime procedure (§1.4).
        assert settings.token_is_valid(TOKEN_A) is True
        assert settings.token_is_valid(TOKEN_B) is True
        assert settings.token_is_valid(secrets.token_urlsafe(32)) is False
        assert settings.token_is_valid("") is False

    def test_origin_check_is_off_when_no_origins_are_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        monkeypatch.delenv("WINSHOW_ALLOWED_ORIGINS", raising=False)
        settings = Settings()
        assert settings.origin_is_allowed("https://anything.example") is True

    def test_absent_origin_is_accepted_even_when_a_list_is_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Non-browser MCP clients send no Origin, and the header exists to stop a browser
        # being used as a confused deputy. Refusing them defends against nothing.
        monkeypatch.setenv("WINSHOW_AGENT_TOKENS", TOKEN_A)
        monkeypatch.setenv("WINSHOW_ALLOWED_ORIGINS", "https://client.example")
        settings = Settings()
        assert settings.origin_is_allowed(None) is True
        assert settings.origin_is_allowed("https://client.example") is True
        assert settings.origin_is_allowed("https://evil.example") is False
