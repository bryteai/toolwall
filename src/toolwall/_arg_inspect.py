"""Request-side argument inspection.

Defends against the simplest argument-smuggling attacks:
* shell metacharacters when the policy bans them,
* URLs outside the allowlist / inside the denylist,
* outbound writes (POST/PUT/PATCH/DELETE) to hosts in ``egress_denylist``,
* path arguments escaping ``Policy.path_scope``,
* per-argument regex validators.

This is *not* a sandbox. It is a coarse, fast filter that runs before the
tool is ever called. The threat model (§4.6) is explicit that this does
not patch an underlying ``eval(arg)`` bug.
"""

from __future__ import annotations

import fnmatch
import os
import urllib.parse
from collections.abc import Mapping
from typing import Any

import regex as re  # type: ignore[import-untyped]

from .exceptions import PolicyViolation
from .policy import Policy

# POSIX shell metacharacters plus a couple of Windows-flavoured ones.
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r\x00]|\$\(|`")


def _host_of(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urllib.parse.urlsplit(url_or_host).hostname or ""
    return url_or_host


def _host_matches(host: str, patterns: tuple[str, ...]) -> bool:
    host = host.lower()
    return any(fnmatch.fnmatch(host, p.lower()) for p in patterns)


def _looks_like_url(value: str) -> bool:
    return value.startswith(("http://", "https://", "ftp://", "file://", "ws://", "wss://"))


def _check_url(value: str, policy: Policy) -> None:
    host = _host_of(value)
    if policy.url_denylist and _host_matches(host, policy.url_denylist):
        raise PolicyViolation(
            "url-denylisted",
            {"host": host, "value": value, "field": "url_denylist"},
        )
    if policy.url_allowlist and not _host_matches(host, policy.url_allowlist):
        raise PolicyViolation(
            "url-not-allowlisted",
            {"host": host, "value": value, "field": "url_allowlist"},
        )


_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_METHOD_ARG_NAMES = ("method", "http_method", "verb")


def _check_egress(bound_args: Mapping[str, Any], policy: Policy) -> None:
    """Block outbound writes to denylisted hosts.

    Applies when the tool takes a method-like argument (``method``,
    ``http_method`` or ``verb``) whose value is POST, PUT, PATCH or DELETE.
    Every URL-valued argument of that call is checked against
    ``Policy.egress_denylist``.
    """
    if not policy.egress_denylist:
        return
    method = next(
        (v.upper() for k, v in bound_args.items() if k.lower() in _METHOD_ARG_NAMES and isinstance(v, str)),
        None,
    )
    if method not in _WRITE_METHODS:
        return
    for name, value in bound_args.items():
        if isinstance(value, str) and _looks_like_url(value):
            host = _host_of(value)
            if _host_matches(host, policy.egress_denylist):
                raise PolicyViolation(
                    "egress-denied",
                    {"host": host, "method": method, "argument": name, "field": "egress_denylist"},
                )


def _check_path(value: str, policy: Policy) -> None:
    if policy.path_scope is None:
        return
    scope = os.path.realpath(os.path.expanduser(policy.path_scope))
    target = os.path.realpath(os.path.expanduser(value))
    if not (target == scope or target.startswith(scope + os.sep)):
        raise PolicyViolation(
            "path-out-of-scope",
            {"value": value, "scope": policy.path_scope, "field": "path_scope"},
        )


def _check_shell(value: str, policy: Policy, arg_name: str) -> None:
    if not policy.shell_metachar_block:
        return
    m = _SHELL_METACHARS.search(value)
    if m is not None:
        raise PolicyViolation(
            "shell-metachar-in-arg",
            {
                "arg": arg_name,
                "span": (m.start(), m.end()),
                "char": value[m.start() : m.end()],
                "field": "shell_metachar_block",
            },
        )


def _check_validator(value: str, policy: Policy, arg_name: str) -> None:
    pattern = policy.arg_validators.get(arg_name)
    if pattern is None:
        return
    if not re.fullmatch(pattern, value):
        raise PolicyViolation(
            "arg-validator-failed",
            {"arg": arg_name, "pattern": pattern, "field": "arg_validators"},
        )


def inspect(
    bound_args: Mapping[str, Any],
    policy: Policy,
    *,
    looks_pathlike: tuple[str, ...] = ("path", "file", "filename", "filepath", "dir", "directory"),
) -> None:
    """Inspect bound arguments and raise on policy violation.

    The traversal is shallow over the top-level argument dict; nested
    arbitrary structures are not recursively inspected by design --- that
    way lies an unbounded checker. Tool authors who pass nested input must
    add ``arg_validators`` entries for the fields they care about.
    """
    _check_egress(bound_args, policy)
    for name, value in bound_args.items():
        _check_validator(str(value) if not isinstance(value, str) else value, policy, name)
        if isinstance(value, str):
            if _looks_like_url(value):
                _check_url(value, policy)
            elif name.lower() in looks_pathlike or (
                policy.path_scope is not None
                and (value.startswith("/") or value.startswith("~") or value.startswith("."))
            ):
                _check_path(value, policy)
            _check_shell(value, policy, name)


__all__ = ["inspect"]
