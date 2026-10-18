"""Build the one-shot final test set from BIPIA (Microsoft, MIT; commit a004b69).

Each email-QA and table-QA test context appears twice: once clean (benign) and once
with one test-split text attack inserted at the start, middle or end (seeded).
Nothing from BIPIA is used for training or model choice.

    python -m bench.external.build_bipia_v0_2 --upstream <BIPIA clone>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "bench" / "build_artifacts" / "final_bipia_v0_2.jsonl"
SEED = 20261022


def build(upstream: Path) -> list[dict]:
    b = upstream / "benchmark"
    rng = random.Random(SEED)
    attacks = [a for v in json.load(open(b / "text_attack_test.json")).values() for a in v]
    rows = []
    for task in ("email", "table"):
        for i, line in enumerate(open(b / task / "test.jsonl")):
            ctx = json.loads(line)["context"]
            rows.append({"id": f"bipia-{task}-{i:03d}-clean", "expected_block": False, "tool_response": ctx, "task": task})
            a = rng.choice(attacks)
            pos = rng.choice(["start", "middle", "end"])
            if pos == "start":
                inj = a + "\n" + ctx
            elif pos == "end":
                inj = ctx + "\n" + a
            else:
                k = len(ctx) // 2
                cut = ctx.rfind("\n", 0, k)
                cut = cut if cut > 0 else k
                inj = ctx[:cut] + "\n" + a + "\n" + ctx[cut:]
            rows.append({"id": f"bipia-{task}-{i:03d}-{pos}", "expected_block": True, "tool_response": inj,
                         "task": task, "position": pos})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", type=Path, default=ROOT / "bench" / "loaders" / "_upstream" / "BIPIA")
    args = ap.parse_args()
    rows = build(args.upstream)
    data = "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    OUT.write_text(data, encoding="utf-8")
    print(len(rows), "rows,", sum(r["expected_block"] for r in rows), "attacked; sha256", hashlib.sha256(data.encode()).hexdigest())


if __name__ == "__main__":
    main()
