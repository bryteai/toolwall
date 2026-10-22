"""Typed handoffs and authority checks for privilege-separated agents.

Type-directed privilege separation (Jacob, Alghamdi, Hu, Alomair and Wagner, arXiv 2509.25926) splits an agent in
two. A quarantined model reads untrusted data; a privileged model picks the actions. The quarantined model may pass
results to the privileged one only as values that cannot carry an instruction: integers, floats, booleans, and
choices from a fixed set of vetted strings (their Table I), plus arrays and records built from these. Free text stays
in opaque variables, which the privileged model cannot read but which can be shown to the user or written into a
tool argument.

This module provides the two checks such a design needs at its boundaries:

* :func:`parse_handoff` validates the quarantined model's output against a schema made of :class:`Int`,
  :class:`Float`, :class:`Bool`, :class:`Enum`, :class:`ArrayOf`, :class:`Record` and :class:`Opaque`. Anything
  else, including any string that is not one of an enum's choices, is rejected. Opaque fields come back as
  :class:`OpaqueValue` handles whose text is hidden from ``str``, ``repr`` and formatting.
* :func:`check_call` runs before a tool call. It refuses an opaque value in an *authority* parameter (the recipient,
  IBAN, URL, participant, channel or object id that decides where the effect lands) and, optionally, any authority
  value outside an allow-list. Opaque values in other parameters are revealed, so the tool receives the text.

What typing does not do: an attacker who writes the data can still change a typed value, for example by choosing a
different enum member or number. On AgentDojo the authority values that are observable only in fields holding an
injection vector are strings (an IBAN, e-mail addresses, a channel name), which this module refuses to pass opaquely.
See ``results/v0_5_agentdojo_census`` for the task-by-task census.
"""
from __future__ import annotations

import math
import secrets
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from .exceptions import PolicyViolation

__all__ = [
    "ArrayOf",
    "Bool",
    "Enum",
    "Float",
    "HandoffError",
    "Int",
    "Opaque",
    "OpaqueValue",
    "Record",
    "Schema",
    "check_call",
    "parse_handoff",
]


class HandoffError(PolicyViolation):
    """The quarantined model's output does not match the handoff schema."""


@dataclass(frozen=True)
class Int:
    """An integer. ``bool`` is rejected even though Python treats it as an ``int``."""

    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True)
class Float:
    """A finite number. Integers are accepted and converted; NaN and infinities are rejected."""

    minimum: float | None = None
    maximum: float | None = None


@dataclass(frozen=True)
class Bool:
    """``True`` or ``False``."""


@dataclass(frozen=True)
class Enum:
    """One of a fixed set of strings chosen by the application designer, not by the data."""

    choices: frozenset[str]

    def __init__(self, choices: Iterable[str]) -> None:
        values = frozenset(choices)
        if not values or not all(isinstance(c, str) for c in values):
            raise ValueError("Enum needs at least one string choice")
        object.__setattr__(self, "choices", values)


@dataclass(frozen=True)
class Opaque:
    """Free text the privileged model must not read. Parsed into an :class:`OpaqueValue`."""

    max_length: int | None = None


@dataclass(frozen=True)
class ArrayOf:
    """A list of ``item`` values, at most ``max_length`` long."""

    item: Schema
    max_length: int | None = None


@dataclass(frozen=True)
class Record:
    """A mapping with exactly these field names."""

    fields: Mapping[str, Schema] = field(default_factory=dict)


Schema: TypeAlias = Int | Float | Bool | Enum | Opaque | ArrayOf | Record


class OpaqueValue:
    """Untrusted text behind a handle. ``str``, ``repr`` and ``format`` show only the handle."""

    __slots__ = ("_text", "handle")

    def __init__(self, text: str) -> None:
        self._text = text
        self.handle = f"$opaque_{secrets.token_hex(4)}"

    def reveal(self) -> str:
        """The text itself, for the user's display or a non-authority tool argument."""
        return self._text

    def __repr__(self) -> str:
        return f"OpaqueValue({self.handle})"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return format(repr(self), spec)


def _fail(path: str, why: str, value: Any) -> HandoffError:
    return HandoffError("handoff-schema-mismatch", {"path": path or "$", "why": why, "type": type(value).__name__})


def parse_handoff(schema: Schema, value: Any, _path: str = "") -> Any:
    """Check ``value`` (already decoded from JSON) against ``schema`` and return the parsed value.

    Raises :class:`HandoffError` on the first mismatch. The error records the path and the type of the offending
    value, never the value itself, so untrusted text does not reach logs or the privileged model through it.
    """
    if isinstance(schema, Bool):
        if not isinstance(value, bool):
            raise _fail(_path, "expected a boolean", value)
        return value
    if isinstance(schema, Int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise _fail(_path, "expected an integer", value)
        if (schema.minimum is not None and value < schema.minimum) or (
            schema.maximum is not None and value > schema.maximum
        ):
            raise _fail(_path, "integer out of range", value)
        return value
    if isinstance(schema, Float):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise _fail(_path, "expected a finite number", value)
        number = float(value)
        if (schema.minimum is not None and number < schema.minimum) or (
            schema.maximum is not None and number > schema.maximum
        ):
            raise _fail(_path, "number out of range", value)
        return number
    if isinstance(schema, Enum):
        if not isinstance(value, str) or value not in schema.choices:
            raise _fail(_path, "not one of the enum's choices", value)
        return value
    if isinstance(schema, Opaque):
        if not isinstance(value, str):
            raise _fail(_path, "expected text", value)
        if schema.max_length is not None and len(value) > schema.max_length:
            raise _fail(_path, "text too long", value)
        return OpaqueValue(value)
    if isinstance(schema, ArrayOf):
        if not isinstance(value, list):
            raise _fail(_path, "expected a list", value)
        if schema.max_length is not None and len(value) > schema.max_length:
            raise _fail(_path, "list too long", value)
        return [parse_handoff(schema.item, v, f"{_path}[{i}]") for i, v in enumerate(value)]
    if isinstance(schema, Record):
        if not isinstance(value, dict):
            raise _fail(_path, "expected an object", value)
        if set(value) != set(schema.fields):
            raise _fail(_path, "fields differ from the schema", value)
        return {k: parse_handoff(s, value[k], f"{_path}.{k}") for k, s in schema.fields.items()}
    raise TypeError(f"unknown schema node {schema!r}")


def _walk(value: Any) -> Iterable[Any]:
    if isinstance(value, Mapping):
        for v in value.values():
            yield from _walk(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _walk(v)
    else:
        yield value


def _reveal(value: Any) -> Any:
    if isinstance(value, OpaqueValue):
        return value.reveal()
    if isinstance(value, Mapping):
        return {k: _reveal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_reveal(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_reveal(v) for v in value)
    return value


def check_call(
    tool: str,
    args: Mapping[str, Any],
    authority: Collection[str],
    *,
    allowed: Mapping[str, Collection[Any]] | None = None,
) -> dict[str, Any]:
    """Check a tool call before it runs and return the arguments with opaque values revealed.

    ``authority`` names the parameters that decide where the effect lands (recipient, IBAN, URL, participants,
    channel, object id). An :class:`OpaqueValue` in one of them raises :class:`PolicyViolation` with reason
    ``opaque-authority-argument``: its text came from data the attacker may have written. If ``allowed`` gives a
    collection for a parameter, every value in it must be a member, or the call fails with
    ``authority-not-allowed``. Other parameters may hold opaque values; the tool receives their text.
    """
    for name in authority:
        if name not in args:
            continue
        for v in _walk(args[name]):
            if isinstance(v, OpaqueValue):
                raise PolicyViolation("opaque-authority-argument", {"tool": tool, "parameter": name})
            if allowed is not None and name in allowed and v not in allowed[name]:
                raise PolicyViolation("authority-not-allowed", {"tool": tool, "parameter": name})
    return {k: _reveal(v) for k, v in args.items()}
