# Security Policy

## Reporting a vulnerability

`toolwall` is a security-adjacent project. We take vulnerability reports seriously.

**Do not file a public GitHub issue for security reports.**

Email: `hasnain@bryteai.studio`
PGP: not yet available — use email.

## Disclosure window

We follow a 90-day coordinated disclosure window from the date of the initial report. We will:

1. Acknowledge receipt within 72 hours.
2. Provide an initial assessment within 7 days.
3. Coordinate a fix, CVE assignment (where applicable), and a public advisory.
4. Credit you in the advisory (opt-in).

If you believe a vulnerability is being actively exploited in the wild, mark the email `[ACTIVE EXPLOIT]` in the subject line; we will compress the disclosure window accordingly.

## Scope

In scope:

- Bypasses of `toolwall` policy enforcement (e.g., a tool response that should be blocked but is not).
- Detector evasion (a known IPI pattern that the shipped detectors miss).
- Side-channel leaks via `toolwall`'s own audit log.
- Supply-chain risks in our published PyPI / npm artifacts.
- Misuse-of-trust in the published Hugging Face datasets and judge model.

Out of scope:

- Direct jailbreaks of the underlying LLM (`toolwall` does not defend the model itself — see [`THREAT_MODEL.md`](THREAT_MODEL.md)).
- Sandbox escapes of the host OS (`toolwall` is application-layer; the host's job).
- Authentication or IAM in tools (assumed to be correctly configured upstream).
- Reports on unsupported versions older than the current minor.

## What we will NOT do

- We will not threaten you with legal action for a good-faith report.
- We will not silently fix a critical vulnerability without an advisory.
- We will not promise rewards for reports unless an explicit bug-bounty program is announced.

— Muhammad Hasnain
