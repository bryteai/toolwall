"""Minimal command-line entry point.

    toolwall check response.json        # score a saved tool response (rules only)
    cat page.txt | toolwall check -      # read from stdin
    toolwall check --judge response.json # also run the judge (needs toolwall-guard[judge]; CPU is fine)
    toolwall proxy --judge -- <mcp server command> [args...]   # protect any stdio MCP server

``check`` exit code: 0 = allowed, 2 = blocked.
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="toolwall", description="Score a tool response for indirect prompt injection.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="score one tool response")
    chk.add_argument("path", help="file to read, or - for stdin")
    chk.add_argument("--judge", action="store_true", help="also run the judge (classifier) layer")
    chk.add_argument("--threshold", type=float, default=0.6)
    prx = sub.add_parser("proxy", help="run an MCP server behind toolwall (stdio)")
    prx.add_argument("--judge", action="store_true", help="also run the judge (classifier) layer")
    prx.add_argument("--threshold", type=float, default=0.6)
    prx.add_argument("--mode", choices=("block", "warn"), default="block",
                     help="block: remove poisoned tools and withhold injected results; warn: audit only")
    prx.add_argument("server", nargs=argparse.REMAINDER, help="-- followed by the MCP server command")
    a = ap.parse_args(argv)

    if a.cmd == "proxy":
        command = a.server[1:] if a.server[:1] == ["--"] else a.server
        if not command:
            ap.error("proxy needs the server command after --")
        from .proxy import run
        return run(command, judge=a.judge, threshold=a.threshold, mode=a.mode)

    if not a.judge:
        os.environ.setdefault("TOOLWALL_DISABLE_JUDGE", "1")
    from .detect import CompositeDetector

    if a.path == "-":
        text = sys.stdin.read()
    else:
        with open(a.path, encoding="utf-8") as fh:
            text = fh.read()
    score, spans = CompositeDetector(use_judge=a.judge).score(text)
    blocked = score >= a.threshold
    print(json.dumps({
        "blocked": blocked,
        "score": round(float(score), 4),
        "threshold": a.threshold,
        "detections": sorted({(s.get("kind") if isinstance(s, dict) else getattr(s, "kind", str(s))) for s in spans}),
    }, indent=2))
    return 2 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
