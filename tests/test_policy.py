"""Tests for :class:`toolwall.Policy` and the built-in factories."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from toolwall import Policy, policy


def test_policy_is_frozen() -> None:
    p = Policy()
    with pytest.raises(ValidationError):
        p.response_max_bytes = 99  # type: ignore[misc]


def test_policy_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        Policy(does_not_exist=True)  # type: ignore[call-arg]


def test_threshold_bounds() -> None:
    Policy(response_ipi_threshold=0.0)
    Policy(response_ipi_threshold=1.0)
    with pytest.raises(ValidationError):
        Policy(response_ipi_threshold=1.5)
    with pytest.raises(ValidationError):
        Policy(response_ipi_threshold=-0.01)


def test_web_fetch_defaults_are_strict() -> None:
    p = policy.web_fetch(url_allowlist=("*.gov.uk",))
    assert p.url_allowlist == ("*.gov.uk",)
    assert p.egress_denylist == ("*",)
    assert p.shell_metachar_block is True
    assert "EMAIL" in p.redact


def test_mcp_locks_schema_by_default() -> None:
    p = policy.mcp()
    assert p.schema_lock is True
    assert p.scan_schema is True


def test_file_read_requires_path_scope() -> None:
    p = policy.file_read(path_scope="/workspace")
    assert p.path_scope == "/workspace"
    assert p.egress_denylist == ("*",)


def test_passthrough_is_explicit() -> None:
    p = policy.passthrough()
    assert p.egress_denylist == ()


def test_policy_round_trips_via_json() -> None:
    p = Policy(
        url_allowlist=("github.com",),
        redact=("EMAIL", "API_KEY"),
        response_max_bytes=42_000,
    )
    blob = p.model_dump_json()
    restored = Policy.model_validate_json(blob)
    assert restored == p


@given(
    threshold=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    max_bytes=st.integers(min_value=0, max_value=10_000_000),
)
def test_policy_property_fuzz(threshold: float, max_bytes: int) -> None:
    p = Policy(response_ipi_threshold=threshold, response_max_bytes=max_bytes)
    assert 0.0 <= p.response_ipi_threshold <= 1.0
    assert p.response_max_bytes >= 0
