"""Built-in redaction patterns.

These are deliberately simple. They are *not* the IPI detector --- see
``toolwall.detect`` for that. The redactor only catches obvious PII / secrets
in tool responses so they cannot enter the model context window even if the
detector judges the response benign.

Adding a pattern here is a stable-API change: downstream policies refer to
patterns by name (``"EMAIL"``, ``"API_KEY"``, ...).
"""

from __future__ import annotations

import regex as re  # type: ignore[import-untyped]

_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
)

# Conservative API-key shape: long base62 / base64-ish runs prefixed by a
# known-vendor token. Avoids matching ordinary long words.
_API_KEY = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9]{20,}"  # OpenAI / Anthropic
    r"|xox[abps]-[A-Za-z0-9-]{10,}"  # Slack
    r"|gh[pousr]_[A-Za-z0-9]{20,}"  # GitHub
    r"|AIza[0-9A-Za-z\-_]{20,}"  # Google
    r"|AKIA[0-9A-Z]{16}"  # AWS access key
    r"|ya29\.[0-9A-Za-z\-_]{20,}"  # Google OAuth
    r")\b"
)

_PHONE_E164 = re.compile(r"(?<![\d])\+[1-9]\d{6,14}(?![\d])")

# US SSN: 3-2-4 with dashes; avoid matching ZIP+4 by requiring middle group.
_SSN_US = re.compile(r"(?<!\d)(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)")

# IBAN: 2 letters + 2 check digits + up to 30 alphanumerics. Whitespace inside is allowed
# by ISO 13616 but we match the compact form; callers can normalize first.
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")

# Credit card: 13--19 digits, optional dashes or spaces, must pass Luhn.
_CC = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")


def _luhn_ok(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_PATTERNS: dict[str, re.Pattern[str]] = {
    "EMAIL": _EMAIL,
    "API_KEY": _API_KEY,
    "PHONE_E164": _PHONE_E164,
    "SSN_US": _SSN_US,
    "IBAN": _IBAN,
    "CREDIT_CARD": _CC,
}


def known_patterns() -> tuple[str, ...]:
    """Names of all built-in redaction patterns."""
    return tuple(_PATTERNS.keys())


def apply(text: str, names: tuple[str, ...]) -> tuple[str, list[dict[str, object]]]:
    """Apply named redactions; return (sanitised_text, list_of_redaction_records).

    Each record is ``{"pattern": <name>, "span": (start, end)}`` --- positions
    refer to the *original* text. The replacement token is the canonical
    ``[REDACTED:<NAME>]`` so the model can see something happened.
    """
    out_parts: list[str] = []
    records: list[dict[str, object]] = []
    pieces: list[tuple[int, int, str]] = []  # (start, end, pattern_name)

    for name in names:
        pat = _PATTERNS.get(name)
        if pat is None:
            continue
        for m in pat.finditer(text):
            if name == "CREDIT_CARD" and not _luhn_ok(m.group(0)):
                continue
            pieces.append((m.start(), m.end(), name))

    if not pieces:
        return text, records

    pieces.sort(key=lambda t: (t[0], -t[1]))
    cursor = 0
    last_end = -1
    for start, end, name in pieces:
        if start < last_end:
            continue  # overlap; first one wins
        out_parts.append(text[cursor:start])
        out_parts.append(f"[REDACTED:{name}]")
        records.append({"pattern": name, "span": (start, end)})
        cursor = end
        last_end = end
    out_parts.append(text[cursor:])
    return "".join(out_parts), records


__all__ = ["apply", "known_patterns"]
