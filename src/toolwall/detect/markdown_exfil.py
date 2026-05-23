"""Markdown / HTML exfiltration-sink detector.

Catches the EchoLeak-class attack: tool response contains a markdown image
(or link) pointing to an attacker-controlled host, often with sensitive data
encoded into the URL path or query string. When the model renders or
auto-fetches the image, the embedded data is exfiltrated.

References
----------
* EchoLeak --- CVE-2025-32711 (CVSS 9.3).
* Microsoft MSRC advisory, June 2025.
* OWASP ASI A07 (2026) --- "Excessive Agency" exfil case studies.
"""

from __future__ import annotations

import fnmatch
import urllib.parse

import regex as re  # type: ignore[import-untyped]

from ._types import Detection

# Markdown: ![alt](URL "title")
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(?P<url>[^()\s]+)(?:\s+\"[^\"]*\")?\s*\)")
# Markdown: [text](URL)
_MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(\s*(?P<url>[^()\s]+)(?:\s+\"[^\"]*\")?\s*\)")
# HTML: <img src=URL>
_HTML_IMG = re.compile(
    r"<img\b[^>]*?\bsrc\s*=\s*(?P<q>[\"'])(?P<url>[^\"']+)(?P=q)",
    re.IGNORECASE,
)
# HTML: <a href=URL>
_HTML_A = re.compile(
    r"<a\b[^>]*?\bhref\s*=\s*(?P<q>[\"'])(?P<url>[^\"']+)(?P=q)",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def _is_allowed(host: str, allowlist: tuple[str, ...]) -> bool:
    if not allowlist:
        return False
    host = host.lower()
    return any(fnmatch.fnmatch(host, p.lower()) for p in allowlist)


def _looks_data_carrying(url: str) -> bool:
    """Heuristic: long query string or long path segment suggests payload."""
    s = urllib.parse.urlsplit(url)
    if len(s.query) >= 40:
        return True
    segments = [seg for seg in s.path.split("/") if seg]
    return any(len(seg) >= 40 for seg in segments)


def detect(text: str, allowlist: tuple[str, ...] = ()) -> list[Detection]:
    """Return detections for markdown / HTML sinks outside ``allowlist``."""
    hits: list[Detection] = []
    for kind, pat in (
        ("markdown-image", _MD_IMAGE),
        ("markdown-link", _MD_LINK),
        ("html-image", _HTML_IMG),
        ("html-link", _HTML_A),
    ):
        for m in pat.finditer(text):
            url = m.group("url")
            host = _host(url)
            if not host:
                continue
            if _is_allowed(host, allowlist):
                continue
            data_carrying = _looks_data_carrying(url)
            # Markdown images are the dangerous shape (auto-fetched); links
            # are merely suspicious unless they carry data.
            base = 0.88 if kind.endswith("-image") else 0.55
            score = min(base + (0.10 if data_carrying else 0.0), 0.97)
            hits.append(
                Detection(
                    kind=f"markdown-exfil/{kind}",
                    span=(m.start(), m.end()),
                    score=score,
                    evidence={
                        "host": host,
                        "url": url[:200],
                        "data_carrying": data_carrying,
                        "source": "EchoLeak CVE-2025-32711",
                    },
                )
            )
    return hits


__all__ = ["detect"]
