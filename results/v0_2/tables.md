### Held-out sets

| Set | n | Metric | **toolwall v0.2** | rules only | ProtectAI v2 |
|---|---:|---|---|---|---|
| InjecAgent, unseen tools × unseen instructions (base) | 95 | ASR | **0.000** [0.000, 0.039] | 0.947 [0.883, 0.977] | 0.284 [0.203, 0.382] |
| InjecAgent, same, "enhanced" setting | 95 | ASR | **0.000** [0.000, 0.039] | **0.000** [0.000, 0.039] | **0.000** [0.000, 0.039] |
| In-house MCP attacks (tool poisoning, rug-pull, exfiltration…) | 185 | ASR | **0.000** [0.000, 0.020] | 0.751 [0.684, 0.808] | 0.319 [0.256, 0.389] |
| Novel attack families (red-team probe) | 10 | ASR | 0.200 [0.057, 0.510] | 0.900 [0.596, 0.982] | **0.000** [0.000, 0.278] |
| deepset/prompt-injections, test split, inside a web page | 60 | ASR | **0.217** [0.131, 0.336] | 0.983 [0.911, 0.997] | 0.517 [0.393, 0.638] |
| Lakera Gandalf, test split, inside a web page | 112 | ASR | 0.205 [0.141, 0.289] | 0.786 [0.701, 0.852] | **0.000** [0.000, 0.033] |
| InjecAgent benign twins (same templates, neutral text) | 150 | FPR | **0.000** [0.000, 0.025] | **0.000** [0.000, 0.025] | 0.287 [0.220, 0.364] |
| Wikipedia articles, random | 400 | FPR | **0.003** [0.000, 0.014] | **0.003** [0.000, 0.014] | 0.180 [0.145, 0.221] |
| Wikipedia security articles (injection, phishing, LLMs) | 91 | FPR | 0.121 [0.069, 0.204] | **0.110** [0.061, 0.191] | 0.319 [0.232, 0.420] |
| Workplace emails containing requests (Enron-Spam ham) | 296 | FPR | **0.000** [0.000, 0.013] | **0.000** [0.000, 0.013] | 0.500 [0.443, 0.557] |
| deepset benign rows, inside a web page | 56 | FPR | **0.000** [0.000, 0.064] | **0.000** [0.000, 0.064] | **0.000** [0.000, 0.064] |
| In-house benign MCP responses | 15 | FPR | **0.000** [0.000, 0.204] | **0.000** [0.000, 0.204] | 0.067 [0.012, 0.298] |
| Short tool outputs (status lines, ids, URLs, listings) | 300 | FPR | **0.000** [0.000, 0.013] | **0.000** [0.000, 0.013] | 0.057 [0.036, 0.089] |

### Final check (BIPIA)

| Set | n | Metric | **toolwall v0.2** | rules only | ProtectAI v2 |
|---|---:|---|---|---|---|
| BIPIA email QA contexts | 50 | ASR | 0.840 [0.715, 0.917] | 0.980 [0.895, 0.996] | **0.480** [0.348, 0.615] |
| BIPIA email QA contexts | 50 | FPR | 0.040 [0.011, 0.135] | **0.020** [0.004, 0.105] | 0.620 [0.482, 0.741] |
| BIPIA table QA contexts | 100 | ASR | 1.000 [0.963, 1.000] | 1.000 [0.963, 1.000] | **0.990** [0.946, 0.998] |
| BIPIA table QA contexts | 100 | FPR | 0.010 [0.002, 0.054] | **0.000** [0.000, 0.037] | 0.020 [0.006, 0.070] |
| BIPIA, both | 150 | ASR | 0.947 [0.898, 0.973] | 0.993 [0.963, 0.999] | **0.820** [0.751, 0.873] |
| BIPIA, both | 150 | FPR | 0.020 [0.007, 0.057] | **0.007** [0.001, 0.037] | 0.220 [0.161, 0.293] |
