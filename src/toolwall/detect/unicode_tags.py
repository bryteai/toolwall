"""Unicode-stealth detectors.

These catch payloads designed to evade human review by encoding instructions
in code-point ranges that render invisibly or below the perception threshold:

* **Unicode Tag block (U+E0000 -- U+E007F).** Riley Goodside demonstrated
  prompt-injection via tag characters against Bing Chat (2024). The block was
  originally intended for language tagging (RFC 2482 / ISO 15924) but is
  never legitimately reached in modern text; any presence is suspicious.
* **Zero-width characters** (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D, BOM
  U+FEFF, WJ U+2060). Documented evasion vector in the OpenAI / Anthropic
  IPI literature and ATTESTMCP attack corpus.
* **Bidirectional overrides** (U+202A--U+202E, U+2066--U+2069). Same class of
  homoglyph / display-reversal attack as `CVE-2021-42574 "Trojan Source"`_.

The detector returns a positive hit when any such character is found in a
tool response. The threat model (§4.2) discusses the false-positive trade
explicitly: we strip-with-audit rather than strip-silently.

.. _CVE-2021-42574 "Trojan Source": https://trojansource.codes/
"""

from __future__ import annotations

import regex as re  # type: ignore[import-untyped]

from ._types import Detection

# U+E0000--U+E007F is the canonical Unicode Tag block.
_TAG_BLOCK = re.compile(r"[\U000E0000-\U000E007F]+")

# Zero-width characters likely to be used to smuggle hidden instructions.
_ZWSP = re.compile(r"[​‌‍⁠﻿]+")

# Bidi overrides --- the Trojan Source family.
_BIDI = re.compile(r"[‪-‮⁦-⁩]+")


def detect(text: str) -> list[Detection]:
    """Return all unicode-stealth detections found in ``text``."""
    hits: list[Detection] = []
    for m in _TAG_BLOCK.finditer(text):
        hits.append(
            Detection(
                kind="unicode-tag",
                span=(m.start(), m.end()),
                score=0.95,
                evidence={
                    "codepoints": [hex(ord(c)) for c in m.group(0)],
                    "source": "Riley Goodside 2024 / DEFCON 32 demo",
                },
            )
        )
    for m in _ZWSP.finditer(text):
        # Single isolated zero-width characters in legitimate text exist
        # (especially in CJK / emoji ZWJ sequences). Score scales with run
        # length --- one ZWSP is suspicious, ten is hostile.
        run = m.end() - m.start()
        score = min(0.55 + 0.05 * run, 0.95)
        hits.append(
            Detection(
                kind="zero-width-run",
                span=(m.start(), m.end()),
                score=score,
                evidence={"length": run, "source": "ATTESTMCP / OWASP ASI A01"},
            )
        )
    for m in _BIDI.finditer(text):
        hits.append(
            Detection(
                kind="bidi-override",
                span=(m.start(), m.end()),
                score=0.90,
                evidence={
                    "codepoints": [hex(ord(c)) for c in m.group(0)],
                    "source": "CVE-2021-42574 Trojan Source",
                },
            )
        )
    return hits


def strip(text: str) -> str:
    """Remove all unicode-stealth runs --- destructive sanitiser.

    Used by the decorator when policy is ``redact``. The original spans are
    already recorded in the audit log by ``detect`` upstream.
    """
    text = _TAG_BLOCK.sub("", text)
    text = _ZWSP.sub("", text)
    text = _BIDI.sub("", text)
    return text


__all__ = ["detect", "strip"]
