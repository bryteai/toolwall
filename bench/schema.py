"""Pydantic models for the toolwall-bench-v0.1 case format.

Every case --- whether imported from InjecAgent, AgentDojo, or curated
in-house --- conforms to this schema. The schema is intentionally
narrow: enough fields to reproduce an attack and grade a defense, no
more. Future versions extend the schema additively (never break the
JSON shape; that would silently invalidate published numbers).
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class AttackKind(str, Enum):
    """The seven families covered by the v0.1 MCP-specific corpus.

    Cases imported from InjecAgent and AgentDojo are mapped onto the
    nearest family or marked ``other``.
    """

    TOOL_POISONING = "tool_poisoning"
    """Malicious instructions embedded in a tool's *description* or
    side-channel metadata fields read by the agent.
    Citation: Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks", 1 April 2025."""

    RUG_PULL = "rug_pull"
    """A tool whose description was benign at approval time but mutated
    post-approval to issue exfiltration / privilege-escalation
    instructions.
    Citation: Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks" (rug-pull section), 1 April 2025."""

    FULL_SCHEMA_POISONING = "full_schema_poisoning"
    """Malicious content in tool input-schema fields the agent reads
    (default values, enum hints, JSON-Schema ``description``).
    Citation: CyberArk (S. Kosman), "Poison everywhere: No output from your MCP server is safe", 30 May 2025."""

    MARKDOWN_EXFIL = "markdown_exfil"
    """EchoLeak-class: response contains a markdown image / link whose
    URL is an attacker-controlled sink with the secret encoded into
    path or querystring.
    Citation: CVE-2025-32711 EchoLeak, Microsoft 365 Copilot."""

    UNICODE_TAG = "unicode_tag"
    """Hidden instructions in invisible Unicode --- U+E0000 tag block,
    zero-width chars, Trojan-Source bidi overrides.
    Citation: Trojan Source CVE-2021-42574; Unicode-tag "ASCII smuggling"
    (J. Rehberger, Embrace The Red, January 2024, crediting R. Goodside)."""

    BASE64_PAYLOAD = "base64_payload"
    """Instructions concealed as base64-, hex- or URL-encoded blobs
    that the agent decodes and follows.
    Citation: Greshake et al., 'Not what you've signed up for', AISec
    2023, §4.2."""

    MULTI_HOP = "multi_hop"
    """Indirect injection chained through a second tool call --- e.g.
    document instructs the agent to read another document, which
    contains the actual payload.
    Citation: AgentDojo (Debenedetti et al., NeurIPS D&B 2024); also
    InjecAgent ``ds`` (deeper) variants."""

    BENIGN = "benign"
    """A legitimate tool response that must NOT be blocked. The
    ``utility`` half of the eval requires that the firewall preserves
    these; over-blocking is as bad as under-blocking."""

    OTHER = "other"
    """Imported case that does not cleanly fit the seven families. We
    keep these for completeness but they are not part of the
    ``new-200`` contribution."""


class Source(str, Enum):
    """Provenance of a case. Mixed into the test split's hash so a
    regenerated bench is identifiable by the SHA-256 alone.
    """

    MCP_V0_1 = "mcp_v0_1"
    INJECAGENT = "injecagent"
    AGENTDOJO = "agentdojo"


class Split(str, Enum):
    TRAIN = "train"
    DEV = "dev"
    TEST = "test"


class Case(BaseModel):
    """One eval case.

    ``tool_response`` is the *raw* string that would be returned by a
    tool call --- a web page body, an MCP tool output, a file content,
    an API JSON. The firewall sees this exact string. No preprocessing.

    ``expected_block`` is the ground truth: True iff a correct defense
    would have refused to pass this response through to the model.

    ``expected_utility_payload`` (optional) is the substring(s) of
    ``tool_response`` that a *good* defense should preserve when the
    case is benign-with-noise --- e.g. the legitimate part of a
    partly-poisoned page. Used to compute the utility score.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    id: str = Field(..., pattern=r"^[a-z0-9_]+-\d{4,}$")
    """Stable identifier; prefix is the source-shortcode, suffix is
    a zero-padded sequence. Once published, an id never changes."""

    attack_kind: AttackKind

    tool_response: str = Field(..., min_length=1, max_length=200_000)
    """The exact string the tool returns."""

    expected_block: bool
    """Ground truth: True if a correct firewall blocks this response."""

    expected_utility_payload: list[str] = Field(default_factory=list)
    """Substrings the firewall should preserve. Empty for blocked-only
    cases. Non-empty for partial-redaction cases or benign cases."""

    source: Source
    citation: str
    """Free-text citation (paper, blog, CVE). Required for
    reproducibility; reviewers will check these."""

    notes: str = ""
    """Optional curator notes. Not used by the scorer."""

    @field_validator("expected_utility_payload")
    @classmethod
    def _payloads_present(cls, v: list[str], info: object) -> list[str]:
        # We do NOT verify substring presence here because some imported
        # cases use canonicalized payloads. The full integrity check
        # runs in bench.build.validate_case_set.
        return v


__all__ = ["AttackKind", "Case", "Source", "Split"]
