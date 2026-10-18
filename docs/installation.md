# Installation

## Requirements
- Python 3.10 or newer (CI tests 3.10 for the core and 3.11–3.13 with the adapters).
- Core dependencies: `pydantic` and `regex` only.
- The judge additionally needs `torch`, `transformers`, `sentencepiece`, `protobuf` and
  `huggingface_hub` (the `judge` extra). It runs on CPU; a GPU is used if available.
- Disk: about 750 MB for the judge weights, downloaded once from the Hugging Face Hub.

## Supported platforms
Pure Python. Developed and tested on Linux (x86-64); expected to work on macOS and Windows
wherever PyTorch is available.

## Install from source
```bash
git clone https://github.com/bryteai/toolwall
cd toolwall
pip install -e .                    # rules and policy only
pip install -e ".[judge]"           # + the classifier
pip install -e ".[adapters]"        # + framework adapters (Anthropic, OpenAI, CrewAI, LangGraph, MCP)
pip install -e ".[dev]"             # + tests and linters
```
A PyPI release as `toolwall-guard` is planned; the PyPI name `toolwall` belongs to an
unrelated project.

## The judge weights
With the `judge` extra installed, the first scored response downloads
`bryteai/toolwall-judge-v0.2` at a pinned revision (see `JUDGE_V02_HF_REVISION` in
`src/toolwall/detect/judge.py`). The weights' SHA-256 is listed in
`bench/build_artifacts/TEST_MANIFEST_v0_2.json`.

Offline use: download the model once (for example with `huggingface-cli download
bryteai/toolwall-judge-v0.2 --local-dir models/judge-v0.2`) and either keep it at
`models/judge-v0.2` in the repository or point `TOOLWALL_JUDGE_LOCAL_PATH` at it.

## Environment variables
| Variable | Effect |
|---|---|
| `TOOLWALL_DISABLE_JUDGE=1` | Rules and policy only; the classifier is never loaded |
| `TOOLWALL_JUDGE_LOCAL_PATH=<dir>` | Load the judge from a local directory instead of the Hub |
| `TOOLWALL_AUDIT_LOG=<file>` | Where audit records are appended (default `./.toolwall-audit.log`) |

If `transformers` is not installed, or the model cannot be loaded, toolwall logs a warning and
continues with rules only. Check the log in production.

## Verify the installation
```bash
python -m pytest -q                          # 86 tests, judge disabled
python examples/arsenal_demo/demo.py         # six example responses
```
