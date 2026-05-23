"""Pattern-matching detector.

Loads ``attack_corpus.csv`` once (lazily) and runs every regex against the
input. Every row in the CSV carries a citation; we refuse to ship patterns
without a public source --- see the CSV columns and threat model §4.1.

This is the cheap-and-deterministic first line of defence. The judge model
(``judge.py``, day 5) handles residual cases.
"""

from __future__ import annotations

import csv
import functools
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
                # A malformed row should not break the import; we ignore and
                # the unit test guards against silent corruption.
                continue
    return rows


def detect(text: str) -> list[Detection]:
    """Return every pattern hit on ``text``.

    Hits do not stop at the first match --- we want the full picture in the
    audit log. Caller (the composite detector) aggregates by max-score.
    """
    out: list[Detection] = []
    for kind, pat, score, source in _compiled():
        for m in pat.finditer(text):
            out.append(
                Detection(
                    kind=kind,
                    span=(m.start(), m.end()),
                    score=score,
                    evidence={
                        "match": m.group(0)[:120],
                        "source": source,
                    },
                )
            )
    return out


def known_kinds() -> tuple[str, ...]:
    """Stable list of detector ``kind`` values; useful for dashboards."""
    return tuple(sorted({k for k, _, _, _ in _compiled()}))


__all__ = ["detect", "known_kinds"]
