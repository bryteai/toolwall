"""Declarative :class:`Policy` and the built-in policy factories.

A :class:`Policy` is a frozen Pydantic model. Once constructed it cannot be
mutated; changes require constructing a new policy. This is intentional --- the
policy is the security contract, and contracts should not be edited in flight.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

OnLowConfidence = Literal["redact", "block", "allow"]


class Policy(BaseModel):
    """Declarative security policy for a single tool boundary.

    Fields are deliberately minimal. Anything that cannot be expressed in
    these fields is either out of scope (see ``THREAT_MODEL.md``) or belongs
    in a separate :class:`Policy` for a separate tool.

    Attributes
    ----------
    url_allowlist:
        Glob patterns. Requests to URLs whose host does not match any entry
        raise :class:`~toolwall.exceptions.PolicyViolation`.
    url_denylist:
        Glob patterns. Requests whose URL host matches raise immediately,
        even if also in ``url_allowlist`` --- denies win.
    egress_denylist:
        Glob patterns of hosts the tool MUST NOT POST / PUT / PATCH to.
        Default ``["*"]`` --- deny-by-default outbound writes.
    path_scope:
        Filesystem root the tool is permitted to read or write under. If
        set, every path argument is normalized and checked to be inside.
    redact:
        Named redaction patterns to apply to tool responses. Built-ins:
        ``"EMAIL"``, ``"API_KEY"``, ``"PHONE_E164"``, ``"SSN_US"``,
        ``"IBAN"``, ``"CREDIT_CARD"``.
    response_max_bytes:
        Cap on raw response size. Exceeding raises
        :class:`~toolwall.exceptions.BudgetExceeded`.
    response_ipi_threshold:
        Detector score (0..1) at or above which to treat as an attack.
    calls_per_min:
        Rate limit applied per-decorated-callable, sliding window.
    cost_cents_max:
        Soft cap on cumulative cost in US cents over the same window.
        ``None`` disables.
    schema_lock:
        If true, refuse calls whose tool schema SHA256 differs from the
        first call observed (rug-pull defence; see threat model §4.3).
    scan_schema:
        If true, run detectors over tool *schema* in addition to response
        (full-schema poisoning defence; see threat model §4.4).
    shell_metachar_block:
        If true, reject string arguments containing shell metacharacters.
        Default ``True``. Set false only if your tool is provably non-shell.
    arg_validators:
        Mapping of argument name to regex. Failing the regex blocks the
        call. The map is exhaustive only over names listed; un-listed args
        are unrestricted.
    on_low_confidence:
        Behaviour when the detector score is in the uncertain band
        (0.3 <= score < ``response_ipi_threshold``):
        ``"redact"`` (default), ``"block"``, ``"allow"``.
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )

    url_allowlist: tuple[str, ...] = ()
    url_denylist: tuple[str, ...] = ()
    egress_denylist: tuple[str, ...] = ("*",)
    path_scope: str | None = None
    redact: tuple[str, ...] = ()
    response_max_bytes: int = Field(default=1_000_000, ge=0)
    response_ipi_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    calls_per_min: int = Field(default=60, ge=0)
    cost_cents_max: int | None = Field(default=None, ge=0)
    schema_lock: bool = False
    scan_schema: bool = False
    shell_metachar_block: bool = True
    arg_validators: dict[str, str] = Field(default_factory=dict)
    on_low_confidence: OnLowConfidence = "redact"


def web_fetch(
    *,
    url_allowlist: tuple[str, ...] = (),
    response_max_bytes: int = 500_000,
    response_ipi_threshold: float = 0.6,
    **overrides: Any,
) -> Policy:
    """Sensible defaults for a web-fetching tool.

    Egress is fully denied by default --- web fetch should never POST.
    Redactions cover the common PII classes a public page might surface.
    """
    base: dict[str, Any] = dict(
        url_allowlist=url_allowlist,
        egress_denylist=("*",),
        redact=("EMAIL", "API_KEY", "PHONE_E164"),
        response_max_bytes=response_max_bytes,
        response_ipi_threshold=response_ipi_threshold,
        shell_metachar_block=True,
    )
    base.update(overrides)
    return Policy(**base)


def file_read(
    *,
    path_scope: str,
    response_max_bytes: int = 1_000_000,
    **overrides: Any,
) -> Policy:
    """Sensible defaults for a file-reading tool.

    Path must be inside ``path_scope`` (chroot-style). No network egress.
    """
    base: dict[str, Any] = dict(
        path_scope=path_scope,
        egress_denylist=("*",),
        redact=("EMAIL", "API_KEY", "SSN_US"),
        response_max_bytes=response_max_bytes,
        shell_metachar_block=True,
    )
    base.update(overrides)
    return Policy(**base)


def mcp(
    *,
    url_allowlist: tuple[str, ...] = (),
    response_max_bytes: int = 500_000,
    **overrides: Any,
) -> Policy:
    """Sensible defaults for an MCP tool boundary.

    Turns on ``schema_lock`` and ``scan_schema`` --- the rug-pull and
    full-schema-poisoning defences --- which are the table stakes
    documented in OWASP ASI A02 and the CyberArk 2026 disclosure.
    """
    base: dict[str, Any] = dict(
        url_allowlist=url_allowlist,
        egress_denylist=("*",),
        redact=("EMAIL", "API_KEY", "PHONE_E164"),
        response_max_bytes=response_max_bytes,
        schema_lock=True,
        scan_schema=True,
        shell_metachar_block=True,
    )
    base.update(overrides)
    return Policy(**base)


def shell(
    *,
    arg_validators: dict[str, str] | None = None,
    **overrides: Any,
) -> Policy:
    """Sensible defaults for a shell-like tool. Shell metachars stay blocked."""
    base: dict[str, Any] = dict(
        egress_denylist=("*",),
        arg_validators=arg_validators or {},
        shell_metachar_block=True,
    )
    base.update(overrides)
    return Policy(**base)


def passthrough() -> Policy:
    """Empty policy --- audit only, no enforcement.

    Useful for staging the library before turning on enforcement, or for
    capturing baseline traffic. Do not use in production.
    """
    return Policy(egress_denylist=())


__all__ = [
    "OnLowConfidence",
    "Policy",
    "file_read",
    "mcp",
    "passthrough",
    "shell",
    "web_fetch",
]
