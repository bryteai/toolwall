# Where a detector belongs: toolwall as the trust boundary

## The argument
Detectors on text can be evaded by an attacker who adapts to them. This has been shown for intrusion detection,
for adversarial-example detectors and for prompt-injection defenses ("The Attacker Moves Second", Nasr et al., 2025,
bypassed 12 recent defenses). The defenses that hold up better change the structure of the system instead of
guessing which text is malicious:

- **StruQ** (Chen, Piet, Sitawarin, Wagner; USENIX Security 2025) sends the prompt and the data through separate
  channels. A secure front-end reserves delimiter tokens for the system and filters them out of the data, so data
  cannot pose as an instruction.
- **SecAlign, Meta-SecAlign, SecPO, SecOPD** (Wagner's group, with Meta FAIR) train models to follow only the trusted
  role and to treat a separate `input` role as data. Their chat templates remove control tokens from untrusted content.
- SecPO and SecOPD state that they **assume the application marks which text is untrusted**; the model does not
  infer that boundary.

That last point is the gap toolwall can fill. An agent's tool outputs are exactly the untrusted text these models
were trained to expect in the `input` role, and toolwall already sits between every tool and the model.

## What toolwall does here (v0.4, unreleased)
- `toolwall.boundary.filter_untrusted(text)` removes the model's control tokens until none is left. It is checked
  against the SecPO Llama template's own filter on 20,000 random strings built from token fragments: **0 differences**
  (`eval/check_boundary_vs_secpo_template.py`).
- `toolwall.boundary.untrusted_messages(task, tool_outputs)` puts the user's request in `user` and each filtered tool
  output in its own `input` message.
- `Policy(untrusted_delimiters=boundary.LLAMA3_DELIMITERS)` applies the filter to every string response of a wrapped
  tool, before redaction and detection, and records `control_tokens_removed` in the audit log. Other models:
  `boundary.delimiters_from_tokenizer(tokenizer)`.

## Measured cost on benign data
| | Benign texts changed or blocked |
|---|---:|
| Boundary filter on SEP (9,160 tasks + 9,160 data), LLMail-Inject benign (703), BIPIA benign (150) | **0 of 19,173** |
| toolwall v0.3 detector on clean SEP data | 103 of 9,160 (1.12 %) |
| PIGuard on clean SEP data | 79 of 9,160 (0.86 %) |

58 of the detector's 103 false alarms are SEP tasks whose data is itself a prompt ("Enhance the following prompt…" with
the data "Create a character for a high fantasy novel."). Text that is an instruction meant to be processed looks
like an injection to a classifier that sees only the data. A role-separated model can tell the two apart by role.
Details: `results/v0_4_sep_clean/README.md`.

## What this does not claim
- The filter adds no security on its own. Security comes from a model trained to respect the `input` role, and is
  limited by that model's own robustness (see the SecPO and SecOPD papers for their adaptive results).
- Only string and bytes responses are filtered; structured results must be serialized first.
- The detector stays useful as a second signal and for models without an `input` role, but it should not be the
  security boundary.

## Next
- Same filter in the MCP proxy (`toolwall proxy --untrusted-delimiters llama3`).
- Least-privilege rules for side effects: an outbound action whose recipient or URL appears only in untrusted tool
  output, and not in the user's request, needs confirmation.
