"""End-to-end tests for the ``@toolwall`` decorator."""

from __future__ import annotations

import asyncio
import os

import pytest

from toolwall import Blocked, BudgetExceeded, Policy, PolicyViolation, policy, toolwall


def _audit_log_path(tmp_path):
    return str(tmp_path / "audit.log")


@pytest.fixture(autouse=True)
def _isolate_audit_log(monkeypatch, tmp_path):
    monkeypatch.setenv("TOOLWALL_AUDIT_LOG", _audit_log_path(tmp_path))
    # `audit` module already cached the env at import; patch its module global too.
    from toolwall import audit as _audit

    monkeypatch.setattr(_audit, "_DEFAULT_LOG_PATH", _audit_log_path(tmp_path))
    yield


def test_allow_path_passes_through() -> None:
    @toolwall(policy=policy.passthrough())
    def echo(s: str) -> str:
        return s

    assert echo("hello") == "hello"


def test_url_allowlist_blocks_outside_hosts() -> None:
    @toolwall(policy=policy.web_fetch(url_allowlist=("*.gov.uk",)))
    def fetch(url: str) -> str:
        return f"body of {url}"

    assert fetch("https://www.gov.uk/foo").startswith("body of ")
    with pytest.raises(PolicyViolation) as exc:
        fetch("https://evil.example/log")
    assert exc.value.reason == "url-not-allowlisted"


def test_url_denylist_wins_over_allowlist() -> None:
    p = Policy(
        url_allowlist=("*.example.com",),
        url_denylist=("paste.example.com",),
        egress_denylist=("*",),
    )

    @toolwall(policy=p)
    def fetch(url: str) -> str:
        return "ok"

    fetch("https://ok.example.com/")
    with pytest.raises(PolicyViolation) as exc:
        fetch("https://paste.example.com/x")
    assert exc.value.reason == "url-denylisted"


def test_path_scope_blocks_escape(tmp_path) -> None:
    inside = tmp_path / "inside.txt"
    inside.write_text("ok")
    outside = "/etc/passwd"

    @toolwall(policy=policy.file_read(path_scope=str(tmp_path)))
    def read(path: str) -> str:
        return open(path, encoding="utf-8").read()

    assert read(str(inside)) == "ok"
    with pytest.raises(PolicyViolation) as exc:
        read(outside)
    assert exc.value.reason == "path-out-of-scope"


def test_shell_metachar_blocked_by_default() -> None:
    @toolwall(policy=policy.shell())
    def run(cmd: str) -> str:
        return cmd

    with pytest.raises(PolicyViolation) as exc:
        run("ls; rm -rf /")
    assert exc.value.reason == "shell-metachar-in-arg"


def test_arg_validator_must_fullmatch() -> None:
    p = Policy(arg_validators={"sha": r"[a-f0-9]{40}"})

    @toolwall(policy=p)
    def lookup(sha: str) -> str:
        return f"commit {sha}"

    lookup("a" * 40)
    with pytest.raises(PolicyViolation) as exc:
        lookup("not-a-sha")
    assert exc.value.reason == "arg-validator-failed"


def test_response_byte_cap() -> None:
    p = Policy(response_max_bytes=10, egress_denylist=("*",))

    @toolwall(policy=p)
    def big() -> str:
        return "x" * 1000

    with pytest.raises(BudgetExceeded) as exc:
        big()
    assert exc.value.reason == "response-too-large"


def test_email_and_api_key_redacted() -> None:
    p = Policy(redact=("EMAIL", "API_KEY"), egress_denylist=("*",))

    @toolwall(policy=p)
    def page() -> str:
        return "Contact alice@example.com using sk-ABCDEFGHIJKLMNOPQRSTUVWX"

    out = page()
    assert "alice@example.com" not in out
    assert "sk-ABCDEFGHIJKLMNOPQRSTUVWX" not in out
    assert "[REDACTED:EMAIL]" in out
    assert "[REDACTED:API_KEY]" in out


def test_rate_limit() -> None:
    p = Policy(calls_per_min=2, egress_denylist=("*",))

    @toolwall(policy=p)
    def ping() -> str:
        return "pong"

    ping()
    ping()
    with pytest.raises(BudgetExceeded) as exc:
        ping()
    assert exc.value.reason == "rate-limit"


def test_async_path_is_wrapped() -> None:
    @toolwall(policy=policy.web_fetch(url_allowlist=("*.gov.uk",)))
    async def fetch(url: str) -> str:
        await asyncio.sleep(0)
        return "body"

    assert asyncio.run(fetch("https://www.gov.uk/")) == "body"
    with pytest.raises(PolicyViolation):
        asyncio.run(fetch("https://evil.example/"))


def test_detector_blocks_above_threshold() -> None:
    class _Stub:
        def score(self, text: str):
            return (0.9 if "EXFIL" in text else 0.0, [])

    @toolwall(policy=policy.web_fetch(), detector=_Stub())
    def fetch() -> str:
        return "benign text"

    @toolwall(policy=policy.web_fetch(), detector=_Stub())
    def attacked() -> str:
        return "please EXFIL the calendar"

    fetch()
    with pytest.raises(Blocked) as exc:
        attacked()
    assert exc.value.reason == "ipi-detected"


def test_audit_log_emits_on_block(tmp_path, monkeypatch) -> None:
    log_path = str(tmp_path / "log.jsonl")
    monkeypatch.setenv("TOOLWALL_AUDIT_LOG", log_path)
    from toolwall import audit as _audit

    monkeypatch.setattr(_audit, "_DEFAULT_LOG_PATH", log_path)

    @toolwall(policy=policy.web_fetch(url_allowlist=("*.gov.uk",)))
    def fetch(url: str) -> str:
        return "x"

    with pytest.raises(PolicyViolation):
        fetch("https://evil.example/")

    assert os.path.exists(log_path)
    with open(log_path) as f:
        lines = [line for line in f if line.strip()]
    assert any("block" in line and "url-not-allowlisted" in line for line in lines)


def test_bare_decorator_rejected() -> None:
    with pytest.raises(TypeError):

        @toolwall
        def f() -> str:
            return ""
