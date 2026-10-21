"""Quickstart: toolwall as the trust boundary for a role-separated model (SecPO / Meta-SecAlign).

Role-separated models are trained to follow the ``user`` role and to treat a separate ``input`` role as data. They
assume the application puts tool output in that role and removes the model's control tokens from it. toolwall does
both: the wrapped tool's responses are filtered, and ``untrusted_messages`` builds the ``user`` / ``input`` messages.

Run with::

    pip install -e ".[judge]"        # from a clone of the repo
    python examples/role_separated/quickstart.py              # prints the rendered prompts (tokenizer only)
    python examples/role_separated/quickstart.py --generate   # also generates (needs a GPU with ~20 GB)

All tool outputs here are benign. The third one is text that is itself an instruction meant to be processed, the
kind of data a detector that reads only the tool output tends to block.
"""

from __future__ import annotations

import argparse

from toolwall import Policy, toolwall
from toolwall.boundary import LLAMA3_DELIMITERS, untrusted_messages

MODEL = "Sizhe-Chen/Llama-3.1-8B-Instruct-SecPO"
REVISION = "c72f78efafdefbcd587cc9abefcd3da518ec7c57"

PAGES = {
    "forecast": "London, Wednesday: light rain in the morning, dry from noon, 14 C, wind from the south-west.",
    "email": ("Hi team, the design review moves from Thursday to Friday at 10:00 because the projector room is "
              "booked. Please bring the latest mock-ups. Thanks, Sara"),
    "prompt": "Create a character for a high fantasy novel.",
}
TASKS = [
    ("What will the weather be like in London on Wednesday?", "forecast"),
    ("Summarize this email in one sentence.", "email"),
    ("Improve the writing prompt below so that it is more specific. Reply with the improved prompt only.", "prompt"),
]


class _NoDetector:  # this example shows the boundary alone; use the default detector in real deployments
    def score(self, text: str) -> tuple[float, list[dict[str, object]]]:
        return 0.0, []


@toolwall(policy=Policy(untrusted_delimiters=LLAMA3_DELIMITERS), detector=_NoDetector())
def fetch(page: str) -> str:
    return PAGES[page]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true")
    a = ap.parse_args()

    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(MODEL, revision=REVISION)
    model = None
    if a.generate:
        import torch
        from transformers import AutoModelForCausalLM

        model = AutoModelForCausalLM.from_pretrained(MODEL, revision=REVISION, torch_dtype=torch.bfloat16,
                                                     device_map="auto")
    for task, page in TASKS:
        messages = untrusted_messages(task, fetch(page))
        prompt = tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        print("=" * 72)
        print(prompt)
        if model is not None:
            ids = tok.apply_chat_template(messages, add_generation_prompt=True, return_tensors="pt").to(model.device)
            out = model.generate(ids, max_new_tokens=200, do_sample=False)
            print("--- model:", tok.decode(out[0][ids.shape[1]:], skip_special_tokens=True).strip())


if __name__ == "__main__":
    main()
