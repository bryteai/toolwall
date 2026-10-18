"""toolwall proxy: end to end over stdio with a fake MCP server (rules only)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

FAKE = str(Path(__file__).parent / "fixtures" / "fake_mcp_server.py")


def _session(messages: list[dict], mode: str = "block", tmp_path: Path | None = None) -> list[dict]:
    env = dict(os.environ, TOOLWALL_DISABLE_JUDGE="1")
    if tmp_path is not None:
        env["TOOLWALL_AUDIT_LOG"] = str(tmp_path / "audit.log")
    proc = subprocess.run(
        [sys.executable, "-m", "toolwall.cli", "proxy", "--mode", mode, "--", sys.executable, FAKE],
        input="".join(json.dumps(m) + "\n" for m in messages), capture_output=True, text=True, env=env, timeout=60,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _call(i: int, city: str) -> dict:
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "weather", "arguments": {"city": city}}}


LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def test_poisoned_tool_description_is_removed(tmp_path) -> None:
    out = _session([LIST], tmp_path=tmp_path)
    names = [t["name"] for t in out[0]["result"]["tools"]]
    assert names == ["weather"]
    assert "schema-poisoned" in (tmp_path / "audit.log").read_text()


def test_injected_tool_output_is_withheld_and_clean_output_passes(tmp_path) -> None:
    out = _session([LIST, _call(2, "Lahore"), _call(3, "evil")], tmp_path=tmp_path)
    by_id = {m["id"]: m["result"] for m in out}
    assert by_id[2]["content"][0]["text"] == "Sunny in Lahore, 21C."
    assert by_id[3]["isError"] is True and "withheld" in by_id[3]["content"][0]["text"]


def test_rug_pull_removes_changed_tool(tmp_path) -> None:
    second = {"jsonrpc": "2.0", "id": 4, "method": "tools/list"}
    out = _session([LIST, second], tmp_path=tmp_path)
    by_id = {m["id"]: m["result"] for m in out}
    assert [t["name"] for t in by_id[1]["tools"]] == ["weather"]
    assert by_id[4]["tools"] == []
    assert "schema-mismatch" in (tmp_path / "audit.log").read_text()


def test_warn_mode_changes_nothing(tmp_path) -> None:
    out = _session([LIST, _call(2, "evil")], mode="warn", tmp_path=tmp_path)
    by_id = {m["id"]: m["result"] for m in out}
    assert [t["name"] for t in by_id[1]["tools"]] == ["weather", "notes"]
    assert by_id[2]["isError"] is False
