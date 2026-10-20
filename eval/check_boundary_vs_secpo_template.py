"""Differential check: toolwall.boundary.filter_untrusted vs the SecPO / Meta-SecAlign Llama chat template filter.

Downloads tokenizer_config.json of Sizhe-Chen/Llama-3.1-8B-Instruct-SecPO at a pinned revision, renders the
template's own `filter_untrusted_content` macro with Jinja (sandboxed, as transformers does) on random strings
built from Llama control-token fragments, and compares with toolwall's filter. Then checks that the filter leaves
the benign texts of the frozen test sets unchanged. Needs: huggingface_hub, jinja2.

    python eval/check_boundary_vs_secpo_template.py
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from toolwall.boundary import LLAMA3_DELIMITERS, filter_untrusted  # noqa: E402

SECPO_REPO = "Sizhe-Chen/Llama-3.1-8B-Instruct-SecPO"
SECPO_REV = "c72f78efafdefbcd587cc9abefcd3da518ec7c57"
CASES, SEED = 20_000, 20261021


def template_filter():
    from huggingface_hub import hf_hub_download
    from jinja2.sandbox import ImmutableSandboxedEnvironment

    cfg = json.loads(Path(hf_hub_download(SECPO_REPO, "tokenizer_config.json", revision=SECPO_REV)).read_text())
    ct = cfg["chat_template"]
    end = "{%- endmacro -%}"
    macro = ct[: ct.index(end) + len(end)]

    def raise_exception(message: str) -> None:
        raise ValueError(message)

    env = ImmutableSandboxedEnvironment(extensions=["jinja2.ext.loopcontrols"], trim_blocks=True, lstrip_blocks=True)
    env.globals["raise_exception"] = raise_exception
    tpl = env.from_string(macro + "{{- filter_untrusted_content(x) -}}")
    return lambda x: tpl.render(x=x)


def main() -> None:
    ref = template_filter()
    rng = random.Random(SEED)
    pieces = [*LLAMA3_DELIMITERS, "<|", "|>", "eot", "_id", "start_header", "end_header", "a", " ", "\n", "é", "{", "}"]
    changed = mismatches = 0
    for _ in range(CASES):
        x = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 30)))
        ours = filter_untrusted(x)
        changed += ours != x
        mismatches += ref(x) != ours
    out = {"secpo_repo": SECPO_REPO, "secpo_revision": SECPO_REV, "cases": CASES, "seed": SEED,
           "changed_by_filter": changed, "mismatches": mismatches}
    benign = {
        "sep_clean (data + task)": [r[k] for r in map(json.loads, open(ROOT / "bench/build_artifacts/sep_clean_v0_4/sep_clean.jsonl", encoding="utf-8")) for k in ("text", "task")],
        "llmail_benign": [r["tool_response"] for r in map(json.loads, open(ROOT / "bench/build_artifacts/final_v0_3/llmail_final_v0_3.jsonl", encoding="utf-8")) if not int(r["expected_block"])],
        "bipia_benign": [r["tool_response"] for r in map(json.loads, open(ROOT / "bench/build_artifacts/final_bipia_v0_2.jsonl", encoding="utf-8")) if not int(r["expected_block"])],
    }
    out["benign_changed"] = {k: {"changed": sum(filter_untrusted(t) != t for t in v), "n": len(v)} for k, v in benign.items()}
    print(json.dumps(out, indent=1))
    (ROOT / "results/v0_4_sep_clean/boundary_check.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
