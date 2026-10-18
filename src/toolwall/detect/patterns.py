"""Pattern-matching detector.

Loads ``attack_corpus.csv`` once (lazily) and runs every regex against the
input. Every row in the CSV carries a citation; we refuse to ship patterns
without a public source --- see the CSV columns and threat model §4.1.

This is the cheap-and-deterministic first line of defence. The judge model
(see :mod:`toolwall.detect.judge`) handles residual cases.

v0.1.0 hardening (2026-05-24, Round 1):
    - Use-vs-mention dampener: matches inside quoted strings or fenced code
      regions get their score halved. Prevents over-blocking on security
      blogs / OWASP write-ups / customer tickets / READMEs that *quote*
      canonical IPI phrases as examples.
    - Encoded-payload decode-and-rescan: long base64 runs are decoded and
      the decoded text rescanned with the same corpus. Hits surface with
      kind ``<original-kind>-encoded-base64`` for clear audit trails.
    - Homoglyph normalize-and-rescan: Cyrillic/Greek/Armenian confusables
      that visually mimic Latin are mapped to Latin and the text rescanned
      with the same corpus. Hits surface with kind ``<original>-homoglyph``.

v0.1.0 hardening (2026-05-24, Round 2 — Endest-level pass):
    - NFKC + ASCII normalisation rescan: handles mathematical alphanumerics
      (U+1D400+), fullwidth (U+FF00+), and any compatibility-decomposable
      variants. Hits surface with kind ``<original>-nfkc``.
    - Combining-mark strip rescan: Zalgo / combining-diacritic obfuscation
      gets stripped via ``unicodedata.category`` checks. Hits surface with
      kind ``<original>-stripped``.
    - Hex decode-and-rescan: long ``[0-9a-fA-F]{40,}`` runs are decoded
      as UTF-8 and rescanned. Hits surface with ``-encoded-hex``.
    - URL-decode-loop-and-rescan: text containing ``%[0-9A-Fa-f]{2}`` is
      iteratively URL-decoded up to 3 times and rescanned. Hits surface
      with ``-encoded-url``.
    - Gzip-magic decode-and-rescan: base64 runs whose decoded bytes start
      with the gzip magic ``\\x1f\\x8b`` are gunzipped before pattern
      match. Hits surface with ``-encoded-gzip``.
"""

from __future__ import annotations

import base64
import csv
import functools
import gzip
import unicodedata
import urllib.parse
from importlib import resources

import regex as re  # type: ignore[import-untyped]

from ._types import Detection


@functools.lru_cache(maxsize=1)
def _compiled() -> list[tuple[str, re.Pattern[str], float, str]]:
    rows: list[tuple[str, re.Pattern[str], float, str]] = []
    with (
        resources.files(__package__).joinpath("attack_corpus.csv").open("r", encoding="utf-8") as fh
    ):
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                flags = re.IGNORECASE if row["case_insensitive"].lower() == "true" else 0
                pattern = re.compile(row["pattern"], flags)
                rows.append((row["kind"], pattern, float(row["score"]), row["source"]))
            except re.error:
                continue
    return rows


# --- Use-vs-mention dampener -------------------------------------------------


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    """Return half-open ranges of quoted / code-fenced regions."""
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i : i + 3] == "```":
            j = text.find("```", i + 3)
            if j < 0:
                break
            spans.append((i, j + 3))
            i = j + 3
            continue
        c = text[i]
        if c == "`":
            nl = text.find("\n", i + 1)
            j = text.find("`", i + 1)
            if j < 0 or (nl >= 0 and nl < j):
                i += 1
                continue
            spans.append((i, j + 1))
            i = j + 1
            continue
        if c in ('"', "'"):
            close = text.find(c, i + 1)
            if close < 0 or close - i > 500:
                i += 1
                continue
            spans.append((i, close + 1))
            i = close + 1
            continue
        i += 1
    return spans


def _in_any_span(pos: int, spans: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in spans)


def _looks_structured(text: str) -> bool:
    """True for JSON / dict / list payloads, where quotes are syntax, not a quotation.

    v0.2.0 fix: the v0.1.1 dampener treated every quoted span as a "mention",
    which includes every string value of a JSON tool response, so canonical
    injections inside structured tool output were halved below the threshold.
    """
    head = text.lstrip()[:1]
    return head in ("{", "[")


# --- Encoded-payload decode-and-rescan ---------------------------------------

_BASE64_RUN = re.compile(r"(?:[A-Za-z0-9+/]{60,}={0,2})")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{40,})")
_URL_ESC = re.compile(r"%[0-9A-Fa-f]{2}")
_GZIP_MAGIC = b"\x1f\x8b"
_ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def _decoded_hits(text: str) -> list[Detection]:
    """Decode plausible encoded runs (base64 / hex / url / gzip) and rescan."""
    out: list[Detection] = []
    seen_b64: set[str] = set()
    seen_hex: set[str] = set()

    # Layer A: base64 (and gzip+base64 stack)
    for m in _BASE64_RUN.finditer(text):
        blob = m.group(0)
        if blob in seen_b64:
            continue
        seen_b64.add(blob)
        try:
            raw = base64.b64decode(blob, validate=True)
        except Exception:
            continue
        # If gzip-magic, try gunzip first
        if raw[:2] == _GZIP_MAGIC:
            try:
                raw = gzip.decompress(raw)
                suffix = "-encoded-gzip"
            except Exception:
                suffix = "-encoded-base64"
        else:
            suffix = "-encoded-base64"
        decoded = raw.decode("utf-8", errors="ignore")
        if len(decoded) < 8:
            continue
        for kind, pat, score, source in _compiled():
            if kind == "encoded-payload":
                continue
            for d in pat.finditer(decoded):
                out.append(
                    Detection(
                        kind=f"{kind}{suffix}",
                        span=(m.start(), m.end()),
                        score=max(0.6, score - 0.05),
                        evidence={
                            "match": d.group(0)[:120],
                            "decoded": decoded[:200],
                            "encoding": suffix[1:],
                            "source": source,
                        },
                    )
                )
        # Stacked: if base64 decode did NOT pattern-hit, try ROT13(decoded)
        # and rescan. Chained encodings (b64+rot13) are the canonical
        # stacked-obfuscation case in HarmBench + InjecAgent.
        rot = decoded.translate(_ROT13_TABLE)
        if rot != decoded:
            for kind, pat, score, source in _compiled():
                if kind == "encoded-payload":
                    continue
                for d in pat.finditer(rot):
                    out.append(
                        Detection(
                            kind=f"{kind}{suffix}-rot13",
                            span=(m.start(), m.end()),
                            score=max(0.6, score - 0.05),
                            evidence={
                                "match": d.group(0)[:120],
                                "decoded_rot13": rot[:200],
                                "encoding": f"{suffix[1:]}+rot13",
                                "source": source,
                            },
                        )
                    )

    # Layer B: hex
    for m in _HEX_RUN.finditer(text):
        blob = m.group(0)
        if blob in seen_hex:
            continue
        seen_hex.add(blob)
        if len(blob) % 2:
            continue
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if len(decoded) < 8:
            continue
        for kind, pat, score, source in _compiled():
            if kind == "encoded-payload":
                continue
            for d in pat.finditer(decoded):
                out.append(
                    Detection(
                        kind=f"{kind}-encoded-hex",
                        span=(m.start(), m.end()),
                        score=max(0.6, score - 0.05),
                        evidence={"match": d.group(0)[:120], "decoded": decoded[:200],
                                  "encoding": "hex", "source": source},
                    )
                )

    # Layer C: URL-encoded loop (up to 3 passes)
    if _URL_ESC.search(text):
        decoded = text
        for _ in range(3):
            try:
                nxt = urllib.parse.unquote(decoded)
            except Exception:
                break
            if nxt == decoded:
                break
            decoded = nxt
        if decoded != text and len(decoded) >= 8:
            for kind, pat, score, source in _compiled():
                if kind == "encoded-payload":
                    continue
                for d in pat.finditer(decoded):
                    out.append(
                        Detection(
                            kind=f"{kind}-encoded-url",
                            span=(0, len(text)),
                            score=max(0.6, score - 0.05),
                            evidence={"match": d.group(0)[:120], "decoded": decoded[:200],
                                      "encoding": "url", "source": source},
                        )
                    )

    return out


# --- Homoglyph normalize-and-rescan -----------------------------------------

_HOMOGLYPH_MAP = str.maketrans(
    {
        # Cyrillic
        "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
        "р": "p", "Р": "P", "с": "c", "С": "C", "у": "y", "У": "Y",
        "х": "x", "Х": "X", "і": "i", "І": "I", "ј": "j", "Ј": "J",
        "ѕ": "s", "Ѕ": "S", "ԁ": "d", "ԛ": "q", "ԝ": "w",
        "В": "B", "Н": "H", "К": "K", "М": "M", "Т": "T",
        "ѡ": "w", "ѵ": "v",
        # Greek
        "α": "a", "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I",
        "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
        "Υ": "Y", "Χ": "X", "Ζ": "Z", "ο": "o", "ν": "v",
        # Armenian
        "օ": "o", "ա": "a", "ո": "n",
        # Cherokee a / o
        "Ꭺ": "A", "Ꮃ": "W", "Ꮯ": "C", "Ꮇ": "M", "Ꭱ": "R",
        # Latin look-alikes from extended Latin
        "ɑ": "a", "ɡ": "g",
    }
)


def _homoglyph_hits(text: str) -> list[Detection]:
    """Normalize visual look-alike letters to Latin and rescan."""
    if all(ord(c) < 128 for c in text):
        return []
    normalized = text.translate(_HOMOGLYPH_MAP)
    if normalized == text:
        return []
    out: list[Detection] = []
    for kind, pat, score, source in _compiled():
        if kind in ("encoded-payload", "xss-inline", "sql-injection-inline", "shell-injection-inline"):
            continue
        for m in pat.finditer(normalized):
            out.append(
                Detection(
                    kind=f"{kind}-homoglyph",
                    span=(m.start(), m.end()),
                    score=max(0.65, score - 0.05),
                    evidence={
                        "match_normalized": m.group(0)[:120],
                        "normalization": "cyrillic-greek-armenian-confusables",
                        "source": source,
                    },
                )
            )
    return out


# --- NFKC + ASCII normalise rescan (Round 2) --------------------------------

def _nfkc_hits(text: str) -> list[Detection]:
    """Normalize mathematical alphanumerics / fullwidth / compatibility forms
    via Unicode NFKC and rescan with the same corpus.

    Catches:
        - Math Bold/Italic/etc. letters (U+1D400-U+1D7FF) → ASCII
        - Fullwidth ASCII (U+FF01-U+FF5E) → ASCII
        - Superscript/subscript digits and letters
        - Other compatibility-decomposable forms
    """
    if all(ord(c) < 0x80 for c in text):
        return []
    normalized = unicodedata.normalize("NFKC", text)
    if normalized == text:
        return []
    out: list[Detection] = []
    for kind, pat, score, source in _compiled():
        if kind in ("encoded-payload", "xss-inline", "sql-injection-inline", "shell-injection-inline"):
            continue
        for m in pat.finditer(normalized):
            out.append(
                Detection(
                    kind=f"{kind}-nfkc",
                    span=(m.start(), m.end()),
                    score=max(0.65, score - 0.05),
                    evidence={
                        "match_normalized": m.group(0)[:120],
                        "normalization": "NFKC",
                        "source": source,
                    },
                )
            )
    return out


# --- Combining-mark strip rescan (Round 2) ----------------------------------

def _strip_combining(text: str) -> str:
    return "".join(c for c in text if unicodedata.category(c) != "Mn")


def _zalgo_hits(text: str) -> list[Detection]:
    """Strip combining (Mn) marks and rescan. Zalgo / diacritic-bury bypass."""
    stripped = _strip_combining(text)
    if stripped == text:
        return []
    out: list[Detection] = []
    for kind, pat, score, source in _compiled():
        if kind in ("encoded-payload", "xss-inline", "sql-injection-inline", "shell-injection-inline"):
            continue
        for m in pat.finditer(stripped):
            out.append(
                Detection(
                    kind=f"{kind}-stripped",
                    span=(m.start(), m.end()),
                    score=max(0.65, score - 0.05),
                    evidence={
                        "match_stripped": m.group(0)[:120],
                        "normalization": "strip-combining-marks",
                        "source": source,
                    },
                )
            )
    return out


# --- Public API --------------------------------------------------------------


def detect(text: str) -> list[Detection]:
    """Return every pattern hit on ``text``.

    Hits do not stop at the first match --- we want the full picture in the
    audit log. Caller (the composite detector) aggregates by max-score.

    Layered score adjustments applied here:
        1. Quote-context dampener halves the score if the match starts
           inside a quoted region or fenced code block. Not applied to
           structured payloads (JSON / dict / list), where quotes are syntax.
        2. Decode-and-rescan layers (base64 / gzip / hex / URL) append hits
           with ``-encoded-<scheme>`` kinds.
        3. Homoglyph rescan appends hits with ``-homoglyph`` kinds.
        4. NFKC rescan appends hits with ``-nfkc`` kinds.
        5. Combining-mark strip rescan appends hits with ``-stripped`` kinds.
    """
    quoted = [] if _looks_structured(text) else _quoted_spans(text)
    out: list[Detection] = []
    for kind, pat, score, source in _compiled():
        for m in pat.finditer(text):
            adj_score = score
            in_quote = _in_any_span(m.start(), quoted)
            if in_quote:
                adj_score = score / 2.0
            out.append(
                Detection(
                    kind=kind,
                    span=(m.start(), m.end()),
                    score=adj_score,
                    evidence={
                        "match": m.group(0)[:120],
                        "source": source,
                        "dampened": in_quote,
                    },
                )
            )
    out.extend(_decoded_hits(text))
    out.extend(_homoglyph_hits(text))
    out.extend(_nfkc_hits(text))
    out.extend(_zalgo_hits(text))
    return out


def known_kinds() -> tuple[str, ...]:
    """Stable list of detector ``kind`` values; useful for dashboards."""
    return tuple(sorted({k for k, _, _, _ in _compiled()}))


__all__ = ["detect", "known_kinds"]
