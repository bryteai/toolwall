"""CPU latency of the v0.3 judge (rules + windowed judge), p50 / p95 over repeated calls.

    CUDA_VISIBLE_DEVICES= python -m eval.latency_v0_3 [--model models/judge-v0.3] [--threads N]

Input text is this repository's README (benign prose), cut or repeated to each length. Results go to
results/v0_3_final/latency_<name>.json.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or platform.machine()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=str(ROOT / "models" / "judge-v0.3"))
    ap.add_argument("--threads", type=int, default=0)
    ap.add_argument("--reps", type=int, default=15)
    args = ap.parse_args()
    os.environ["TOOLWALL_JUDGE_LOCAL_PATH"] = args.model
    import torch

    if args.threads:
        torch.set_num_threads(args.threads)
    from toolwall.detect import CompositeDetector, judge

    det = CompositeDetector(use_judge=True)
    base = (ROOT / "README.md").read_text(encoding="utf-8")
    det.score(base[:500])  # load the model once, outside the timings
    out = {"model": Path(args.model).name, "device": judge._win.get("device"), "torch_threads": torch.get_num_threads(),
           "cpu": _cpu_model(), "cores": os.cpu_count(), "rows": []}
    for n in (500, 2000, 8000, 32000):
        text = (base * (n // len(base) + 1))[:n]
        ts = []
        for _ in range(args.reps):
            t0 = time.perf_counter()
            det.score(text)
            ts.append(time.perf_counter() - t0)
        windows = len(judge._windows("", text))
        ts.sort()
        row = {"chars": n, "windows": windows, "p50_s": round(statistics.median(ts), 3),
               "p95_s": round(ts[min(len(ts) - 1, int(0.95 * len(ts)))], 3)}
        out["rows"].append(row)
        print(row, flush=True)
    name = Path(args.model).name
    (ROOT / "results" / "v0_3_final" / f"latency_{name}.json").write_text(json.dumps(out, indent=1) + "\n")


if __name__ == "__main__":
    main()
