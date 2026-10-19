# Installation

## Requirements
- Python 3.10 or newer (CI tests 3.10 for the core and 3.11–3.13 with the adapters).
- Core dependencies: `pydantic` and `regex` only.
- The judge additionally needs `torch`, `transformers`, `sentencepiece`, `protobuf` and
  `huggingface_hub` (the `judge` extra). It runs on CPU; a GPU is used if available.
- Disk: about 740 MB for the judge weights (280 MB for the xsmall variant), downloaded once from the Hugging Face Hub.

## Supported platforms
Pure Python. Developed and tested on Linux (x86-64); expected to work on macOS and Windows
wherever PyTorch is available.

## Install from PyPI
```bash
pip install toolwall-guard                  # rules and policy only
pip install "toolwall-guard[judge]"         # + the classifier
pip install "toolwall-guard[adapters]"      # + framework adapters (Anthropic, OpenAI, CrewAI, LangGraph, MCP)
```
The distribution is called `toolwall-guard`; you import `toolwall` and run the `toolwall`
command. The PyPI name `toolwall` belongs to an unrelated project.

## Install from source
```bash
git clone https://github.com/bryteai/toolwall
cd toolwall
pip install -e ".[judge,dev]"       # classifier + tests and linters
```

## The judge weights
With the `judge` extra installed, the first scored response downloads
`bryteai/toolwall-judge-v0.3` at a pinned revision (see `JUDGE_V03_HF_REVISION` in
`src/toolwall/detect/judge.py`). The weights' SHA-256 is in the
[model card](https://huggingface.co/bryteai/toolwall-judge-v0.3).

| `TOOLWALL_JUDGE` | Model | Notes |
|---|---|---|
| `v0.3` (default) | `bryteai/toolwall-judge-v0.3`, 184M parameters | 0.27 s for 500 characters, 8.7 s for 8,000 on a laptop CPU |
| `v0.3-xsmall` | `bryteai/toolwall-judge-v0.3-xsmall`, 71M | about 2.5 times faster |
| `v0.2` | `bryteai/toolwall-judge-v0.2` | reads only the first 512 tokens |

Offline use: download the model once (for example with `huggingface-cli download
bryteai/toolwall-judge-v0.3 --local-dir models/judge-v0.3`) and either keep it at
`models/judge-v0.3` in the repository or point `TOOLWALL_JUDGE_LOCAL_PATH` at it.

## Environment variables
| Variable | Effect |
|---|---|
| `TOOLWALL_DISABLE_JUDGE=1` | Rules and policy only; the classifier is never loaded |
| `TOOLWALL_JUDGE=<name>` | Pick a published judge: `v0.3` (default), `v0.3-xsmall` or `v0.2` |
| `TOOLWALL_JUDGE_LOCAL_PATH=<dir>` | Load the judge from a local directory instead of the Hub |
| `TOOLWALL_JUDGE_MAX_CHARS=<n>` | Longest text the v0.3 judge scores in full (default 200,000); longer text is scored on its first and last `n/2` characters |
| `TOOLWALL_AUDIT_LOG=<file>` | Where audit records are appended (default `./.toolwall-audit.log`) |

If `transformers` is not installed, or the model cannot be loaded, toolwall logs a warning and
continues with rules only. Check the log in production.

## Verify the installation
```bash
python -m pytest -q                          # 86 tests, judge disabled
python examples/arsenal_demo/demo.py         # six example responses
```
