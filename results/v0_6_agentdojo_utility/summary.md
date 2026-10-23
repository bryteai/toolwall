| Model | Policy | Repeats | Utility (95 % CI) | NO_AUTHORITY_ARG | PROMPT | CLEAN | TAINTED | UNOBSERVED |
|---|---|---:|---|---:|---:|---:|---:|---:|
| deepseek-chat | none | 3 | 90.4 % (84.5–95.2) | 93 % (n=45) | 81 % (n=12) | 90 % (n=28) | 91 % (n=11) | 100 % (n=1) |
| deepseek-chat | prompt_only | 3 | 52.6 % (43.0–62.2) | 92 % (n=45) | 72 % (n=12) | 0 % (n=28) | 0 % (n=11) | 100 % (n=1) |
| deepseek-chat | provenance | 3 | 80.1 % (72.5–86.9) | 92 % (n=45) | 78 % (n=12) | 93 % (n=28) | 0 % (n=11) | 100 % (n=1) |
| deepseek-reasoner | none | 3 | 92.8 % (87.6–96.9) | 93 % (n=45) | 75 % (n=12) | 99 % (n=28) | 94 % (n=11) | 100 % (n=1) |
| deepseek-reasoner | prompt_only | 3 | 54.0 % (44.0–63.6) | 93 % (n=45) | 81 % (n=12) | 0 % (n=28) | 0 % (n=11) | 100 % (n=1) |
| deepseek-reasoner | provenance | 3 | 82.1 % (74.6–89.0) | 93 % (n=45) | 83 % (n=12) | 95 % (n=28) | 0 % (n=11) | 100 % (n=1) |
| ground-truth | none | 1 | 100.0 % (100.0–100.0) | 100 % (n=45) | 100 % (n=12) | 100 % (n=28) | 100 % (n=11) | 100 % (n=1) |
| ground-truth | prompt_only | 1 | 61.9 % (51.5–71.1) | 100 % (n=45) | 100 % (n=12) | 7 % (n=28) | 0 % (n=11) | 100 % (n=1) |
| ground-truth | provenance | 1 | 88.7 % (81.4–94.8) | 100 % (n=45) | 100 % (n=12) | 100 % (n=28) | 0 % (n=11) | 100 % (n=1) |
