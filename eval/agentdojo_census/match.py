"""Value matching shared by the census (census.py) and the runtime policy (../agentdojo_utility).

A tool output is compared in two runs: the benign one and one with every injection vector filled with a canary
(extract_traces.py). A leaf of the benign output is *attacker-writable* if the same leaf holds a canary in the second
run. Matching is exact for whole fields and word-bounded inside longer text.
"""
import re

VOLATILE = {"timestamp", "last_modified"}   # wall-clock fields that differ between any two runs
CANARY = "ZQXCANARY"
# share_file's permission is the enum {'r', 'rw'}; 'r' is the user's "read permissions" (tasks 32, 37).
MANUAL_SOURCE = {("share_file", "permission", "r"): "PROMPT"}


def leaves(v):
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from leaves(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from leaves(x)
    elif v is not None:
        yield v


def fields(b, c, path=""):
    """Yield (path, benign_leaf, attacker_text_in_leaf, derived_change) walking both runs together."""
    if isinstance(b, dict) and isinstance(c, dict):
        for k in b:
            yield f"{path}.{k}#key", k, False, False
            yield from fields(b[k], c.get(k), f"{path}.{k}")
    elif isinstance(b, list) and isinstance(c, list) and len(b) == len(c):
        for i, (x, y) in enumerate(zip(b, c)):
            yield from fields(x, y, f"{path}[{i}]")
    elif isinstance(b, (dict, list)):
        for x in leaves(b):          # structure differs between the runs: treat all of it as attacker text
            yield path, x, True, False
    else:
        writable = CANARY in str(c)
        name = path.rsplit(".", 1)[-1]
        derived = (not writable) and b != c and name not in VOLATILE
        yield path, b, writable, derived


def arg_values(v):
    """Values inside an argument (dict keys are field names, not values)."""
    if isinstance(v, dict):
        for x in v.values():
            yield from arg_values(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            yield from arg_values(x)
    else:
        yield v


def norm(s):
    return re.sub(r"\s+", " ", str(s)).strip().lower()


def matches(value, leaf):
    """Exact equality for whole fields; word-bounded occurrence for strings inside longer text."""
    if isinstance(value, bool) or isinstance(leaf, bool):
        return value == leaf and type(value) is type(leaf)
    if isinstance(value, (int, float)) and isinstance(leaf, (int, float)):
        return value == leaf
    v, s = norm(value), norm(leaf)
    if not v:
        return False
    if v == s:
        return True
    return re.search(r"(?<![\w@.-])" + re.escape(v) + r"(?![\w@-])", s) is not None


def in_prompt(value, prompt):
    if isinstance(value, bool):
        return False
    v = str(value)
    if re.fullmatch(r"\d+", v):      # a bare number in the prompt ("June 13") is not an object id
        return re.search(r"\b(id|ids|file|event|transaction)\W{0,3}['\"]?" + re.escape(v) + r"\b", prompt, re.I) is not None
    return matches(value, prompt)


def authority_items(param, val):
    """The values of one argument; an attachment is {"type": "file", "file_id": ...} and only the id selects an object."""
    items = [a.get("file_id") if isinstance(a, dict) else a for a in val] if param == "attachments" and isinstance(val, list) else val
    return [v for v in arg_values(items) if v is not None and not (isinstance(v, str) and not v)]


def plain(x):
    """A tool result as JSON-like data (pydantic models dumped), as extract_traces.py records it."""
    from pydantic import BaseModel
    if isinstance(x, BaseModel):
        return plain(x.model_dump(mode="json"))
    if isinstance(x, dict):
        return {str(k): plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [plain(v) for v in x]
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x
    return str(x)


def variants(value):
    """The value and the same target as agents also write it: a URL without "http(s)://" or a trailing slash, and
    the address inside "Name <address>". Data and prompts give the bare form; models often add the decoration."""
    out = [value]
    if isinstance(value, str):
        v = value.strip()
        m = re.fullmatch(r"(?i)https?://(.+?)/?", v)
        if m:
            out.append(m.group(1))
        m = re.fullmatch(r"[^<>]*<\s*([^<>\s]+@[^<>\s]+)\s*>", v)
        if m:
            out.append(m.group(1))
    return out
