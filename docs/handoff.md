# Typed handoffs and authority checks (v0.5, unreleased)

## Why
A system-level defense keeps untrusted data away from the part of the agent that chooses actions. Type-directed
privilege separation (Jacob, Alghamdi, Hu, Alomair and Wagner, arXiv 2509.25926) widens what such a design can do: a
quarantined model reads the data and may hand the privileged model integers, floats, booleans and choices from a fixed
set of vetted strings (their Table I), which cannot carry an instruction. Free text stays in opaque variables, which
the privileged model cannot read but which can be shown to the user or written into a tool argument.

Two checks make that design hold at runtime, and both are easy to get subtly wrong:

1. **The handoff itself.** The quarantined model's output must contain nothing but the declared types. In Python a
   `bool` is an `int`, `NaN` is a `float`, and an "enum" that accepts any string the model writes is a string.
2. **Where opaque text may go.** An opaque variable written into the *body* of an e-mail is fine. The same variable
   written into the *recipient* or the IBAN of a payment lets whoever wrote the data choose where the effect lands, without
   any instruction reaching the privileged model.

## API
```python
from toolwall.handoff import Record, ArrayOf, Enum, Float, Opaque, parse_handoff, check_call

slots = Enum(["09:00", "10:00", "14:00"])            # chosen by the application, not by the data
schema = Record({"times": ArrayOf(slots, max_length=5), "amount": Float(minimum=0), "note": Opaque(max_length=500)})

handoff = parse_handoff(schema, quarantined_json)    # raises HandoffError on any mismatch
handoff["note"]                                       # OpaqueValue($opaque_3f9c...): text hidden from str/repr/format

args = check_call(
    "send_money",
    {"recipient": user_given_iban, "amount": handoff["amount"], "subject": handoff["note"]},
    authority={"recipient"},                         # parameters that decide where the effect lands
    allowed={"recipient": known_payees},             # optional allow-list
)                                                     # opaque text revealed only in non-authority parameters
```
- `parse_handoff` rejects booleans where numbers are expected, non-finite floats, strings outside an enum, missing or
  extra record fields and over-long arrays or text. Its errors record the path and the type, never the value, so
  untrusted text does not leak through logs.
- `check_call` raises `PolicyViolation("opaque-authority-argument")` when an opaque value reaches an authority
  parameter, and `PolicyViolation("authority-not-allowed")` when an allow-list is given and a value is not on it.

## What it does not do
Typing stops an attacker from turning data into an instruction. It does not stop the attacker who writes the data from
changing a typed value, for example choosing another member of an enum or another number. For authority parameters,
use values from the user's request or an allow-list. `results/v0_5_agentdojo_census` measures how often each case
occurs on AgentDojo.
