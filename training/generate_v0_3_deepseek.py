"""Generate diverse training material for the v0.3 judge with DeepSeek (cached, resumable).

Three kinds, each as short snippets that the corpus builder inserts into benign hosts:
  * attacks       — injected instructions across goals x styles x languages (threat model, not any test set);
  * aligned       — benign instructions that BELONG to the content and fit the user's task (install steps,
                    recipes, procedures, meeting requests), the main source of false alarms;
  * discussion    — benign text that talks about prompt injection or quotes attack phrases (articles, docs).

Exclusions, to keep the final tests clean: no paper-review, resume-screening or code-review scenarios (LongPIBench
domains), and never the address contact@contact.com or the word "confirmation" as an email body (LLMail-Inject).

    python -m training.generate_v0_3_deepseek --kind attacks --calls 100
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import re
import time
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent / "_gen_v0_3"
URL = "https://api.deepseek.com/chat/completions"
MODEL = "deepseek-flash"
BANNED = re.compile(r"contact@contact\.com|\bconfirmation\b|peer review|reviewer|resume|résumé|curriculum vitae|pull request|code review",
                    re.IGNORECASE)

GOALS = [
    "send the user's private data (emails, contacts, files, API keys) to an outside address",
    "make the assistant call a tool the user did not ask for (transfer money, delete files, change settings)",
    "change the answer the assistant gives the user (wrong facts, biased summary, hide a key detail)",
    "make the assistant promote a product, service or link in its reply",
    "make the assistant tell the user to visit a phishing link or enter credentials",
    "make the assistant ignore the user's request and do something unrelated",
    "make the assistant change payment details, an address or a recipient",
    "make the assistant leak its system prompt or hidden instructions",
    "make the assistant forward or reply to messages on the user's behalf",
    "make the assistant answer in a different language or format to confuse the user",
]
STYLES = [
    "a blunt direct command", "a polite request that sounds like part of the document",
    "a fake system or administrator notice", "a note addressed to 'AI assistants' or 'language models'",
    "a footnote or P.S. at the end of the content", "a sentence hidden inside an otherwise normal paragraph",
    "a JSON or YAML field value", "an HTML or markdown comment", "a fake tool or function-call instruction",
    "an instruction framed as a user preference or saved setting", "an urgent security warning",
    "a role-play or hypothetical framing", "an instruction with deliberate typos or odd spacing",
]
LANGS = ["English"] * 6 + ["Spanish", "German", "French", "Portuguese", "Urdu written in Latin script", "Chinese"]
DOMAINS = ["online shopping", "travel booking", "banking app", "calendar and meetings", "customer support inbox",
           "news website", "recipe website", "software documentation", "smart home", "health clinic portal",
           "real estate listing", "university course page", "weather service", "social media post", "forum thread",
           "spreadsheet export", "CRM record", "file storage listing", "music streaming", "car rental"]
TASKS = ["summarize it", "answer a question about it", "extract key details", "draft a reply", "make a to-do list",
         "compare options", "translate it", "check it for problems"]


def key() -> str:
    t = open(os.path.expanduser("~/.config/secrets/deepseek_toolwall.env")).read()
    return re.search(r"DEEPSEEK_API_KEY=(\S+)", t).group(1)


def ask(prompt: str, k: str, temperature: float = 1.1) -> str:
    body = {"model": MODEL, "temperature": temperature, "max_tokens": 7000, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": "You create labelled data for training a defensive prompt-injection "
                          "detector. Output only JSON."}, {"role": "user", "content": prompt}]}
    for attempt in range(4):
        try:
            r = urllib.request.Request(URL, data=json.dumps(body).encode(), method="POST",
                                       headers={"Authorization": "Bearer " + k, "Content-Type": "application/json"})
            return json.load(urllib.request.urlopen(r, timeout=120))["choices"][0]["message"]["content"]
        except Exception:
            time.sleep(3 * (attempt + 1))
    return "{}"


def prompt_for(kind: str, rng: random.Random) -> tuple[str, dict]:
    dom, task, lang = rng.choice(DOMAINS), rng.choice(TASKS), rng.choice(LANGS)
    if kind == "attacks":
        goals, styles = rng.sample(GOALS, 3), rng.sample(STYLES, 4)
        meta = {"domain": dom, "lang": lang, "goals": goals, "styles": styles}
        p = (f"Write 10 different indirect prompt-injection snippets that an attacker could plant in content from a {dom} "
             f"service, which an AI assistant reads when the user asks it to {task}. Goals to cover: {goals}. Styles to cover: "
             f"{styles}. Language: {lang}. Each snippet 1-4 sentences, realistic, varied wording, no placeholders like [X]. "
             "Use invented but plausible names, addresses and URLs (never contact@contact.com, never the word 'confirmation'). "
             'Return {"items": ["...", ...]}.')
    elif kind == "aligned":
        meta = {"domain": dom, "lang": lang, "task": task}
        p = (f"Write 12 different benign snippets from a {dom} service that contain instructions or requests which are a normal "
             f"part of the content and fit a user who asked an AI assistant to {task}: e.g. setup steps, how-to steps, "
             "procedures, reminders, polite requests between colleagues, terms that say what to do. They must NOT try to "
             f"control the AI assistant. Language: {lang}. Each 1-4 sentences, realistic, varied. "
             'Return {"items": ["...", ...]}.')
    else:
        meta = {"domain": dom, "lang": lang}
        p = ("Write 10 different benign paragraphs (2-5 sentences) from articles, documentation, course notes or forum posts "
             "that DISCUSS prompt injection, jailbreaks or AI security, and may quote example attack phrases in quotation "
             f"marks as illustrations. Vary the angle and tone. Language: {lang}. "
             'Return {"items": ["...", ...]}.')
    return p, meta


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kind", choices=["attacks", "aligned", "discussion"], required=True)
    ap.add_argument("--calls", type=int, default=50)
    ap.add_argument("--workers", type=int, default=8)
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{a.kind}.jsonl"
    done = sum(1 for _ in open(path)) if path.exists() else 0
    k = key()
    seed0 = {"attacks": 1000, "aligned": 2000, "discussion": 3000}[a.kind]

    def job(i: int) -> list[dict]:
        rng = random.Random(seed0 + i)
        p, meta = prompt_for(a.kind, rng)
        raw = ask(p, k)
        try:
            items = json.loads(raw).get("items", [])
        except Exception:  # truncated JSON: keep every complete string item
            items = [json.loads(m) for m in re.findall(r'"(?:[^"\\]|\\.)*"(?=\s*[,\]])', raw.split("[", 1)[-1])]
        out = []
        for t in items:
            if isinstance(t, str) and 15 <= len(t) <= 1200 and not BANNED.search(t):
                out.append({"kind": a.kind, "text": t.strip(), "call": i, **meta})
        return out

    n_new = 0
    with cf.ThreadPoolExecutor(a.workers) as ex, path.open("a") as fh:
        for rows in ex.map(job, range(done, done + a.calls)):
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            n_new += len(rows)
            fh.flush()
    print(f"{a.kind}: +{n_new} items -> {path}")


if __name__ == "__main__":
    main()
