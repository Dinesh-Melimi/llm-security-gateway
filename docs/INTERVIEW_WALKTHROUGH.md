# Interview Walkthrough

A plain-language tour of every component, then likely interview questions with answers.

## The problem in one paragraph

Companies want employees and apps to use LLMs, but each direct call to an LLM API is a place where customer data can leak out, attackers can hijack the model with crafted text, costs can spike, and security has no record of who used what. This gateway puts one checkpoint in front of the LLM. Apps call the gateway instead of the provider; the gateway checks the request, forwards a cleaned version, checks the answer, and logs the decision.

## Request flow (follow `gateway/main.py` top to bottom)

1. **Validate the shape** (Pydantic `ChatRequest`). Rejects malformed bodies, unknown roles, more than 100 messages or 100k characters per message. Cheap protection against junk and oversized requests.
2. **Authenticate** (`auth.py`). The client sends `Authorization: Bearer <key>`. We hash it with SHA-256 and compare against stored digests using `hmac.compare_digest` (constant time, so response timing does not reveal partial matches). The config file never contains real keys, so leaking it does not leak credentials. Failures are logged with the source IP.
3. **Rate limit** (`ratelimit.py`). Sliding window: keep timestamps of each client's recent requests; if there are already N in the last 60 seconds, return 429 with `Retry-After`. Protects cost and availability.
4. **Policy** (`policy.py`, `config/policy.yaml`). Each client belongs to a team. The team's policy says which models are allowed, the max tokens (we clamp, never raise), and blocked topics (whole-word match). This is "policy as code" - reviewable in a pull request.
5. **Prompt-injection scan** (`guardrails/injection.py`). Text is normalized (Unicode NFKC, zero-width characters removed) and run against 13 regex rules, each with a weight. Scores combine with noisy-OR: `1 - product(1 - weight)`. Example: two rules at 0.5 give 0.75, not 1.0. One strong signal (like "ignore all previous instructions", 0.8) blocks alone; a weak one (like "developer mode", 0.5) needs company. Only `user` messages are scanned - `system` messages come from the app owner and are trusted.
6. **PII and secret scan** (`guardrails/pii.py`). Regexes find emails, phones, SSN-format numbers, credit cards, AWS keys, private keys. Validators cut false positives: credit cards must pass the **Luhn checksum**; SSNs with impossible area numbers (000, 666, 9xx) are ignored. Policy: **PII is redacted** (replaced with `[REDACTED_EMAIL]` etc.) so the request still works; **secrets block the request** because a credential in a prompt is already an incident and should not leave the network.
7. **Plant the canary**. A unique marker (`CANARY-7f3a9c`) is added to the system prompt. It never appears anywhere else, so if it shows up in the model's answer, the model leaked its system prompt.
8. **Call the provider** (`providers.py`). A small interface with one method, `complete()`. The mock provider echoes the user message - deterministic, offline, perfect for tests and demos. The OpenAI-compatible provider works with OpenAI, vLLM, Ollama, LiteLLM. Any upstream exception becomes a 502 (fail closed).
9. **Output scan** (`guardrails/output.py`). Canary present: withhold the entire response. PII present: redact it before returning.
10. **Audit** (`audit.py`). One JSON line per decision: timestamp, event ID, client, team, model, decision (allowed / redacted / blocked / error), reason, matched rules, detection types, tokens, latency. The prompt is stored only as a SHA-256 hash. The event ID is returned to the caller so support tickets can be traced to log lines.

## Supporting pieces

- **`scripts/usage_report.py`** - reads the audit log and prints per-client requests, blocks, tokens, and models used, plus top block reasons and detection types. This is the Shadow-AI governance view: who is using AI, for what, and how risky it looks.
- **`scripts/evaluate.py` + `eval/injection_dataset.jsonl`** - 50 labeled prompts. Reports TP/FP/TN/FN, precision, recall, F1, and prints every mistake. Current: precision 0.95, recall 0.80.
- **Tests** - unit tests for each guardrail and API tests for every pipeline branch (auth fail, rate limit, model denied, injection, secret, redaction, canary leak via a fake "leaky" provider, upstream failure, hashed audit). A test also enforces a minimum precision/recall so detector regressions fail CI.
- **CI** - ruff (lint, includes security rules), bandit (Python SAST), pip-audit (known-vulnerable dependencies), pytest, evaluation.
- **Dockerfile** - slim base, non-root user, healthcheck, no dev dependencies or tests in the image.

## Interview Q&A

**Q: Why a gateway instead of a library inside each app?**
One enforcement point means consistent policy, central logging, and no reliance on every team integrating correctly. It also gives visibility into AI usage you would otherwise miss (Shadow AI). The trade-off is an extra network hop and a single point of failure, so it needs to be horizontally scalable.

**Q: Regex for prompt injection? Isn't that weak?**
Yes, and I say so in the README. It is a cheap, explainable first layer that stops copy-paste attacks with near-zero latency. I measured it: 0.95 precision, 0.80 recall on my dataset, and I list what it misses. The detector sits behind a simple function so an ML classifier can be added as a second layer. Prompt injection has no complete fix today; defense in depth (least-privilege tools, output checks, monitoring) matters more than any single filter.

**Q: Why noisy-OR instead of summing scores?**
Summing can exceed 1 and makes thresholds hard to reason about. Noisy-OR stays in [0, 1], treats each rule as independent evidence, and gives diminishing returns, so many weak signals approach but never jump past the threshold unrealistically.

**Q: How do you choose the threshold?**
Trade-off between blocking users (false positives) and letting attacks through (false negatives). `make eval` with `--threshold` shows precision/recall at each point. For a customer-facing chatbot I would lean toward higher recall; for internal developer tools, higher precision to avoid friction.

**Q: Why redact PII but block secrets?**
PII is often legitimately part of a task ("draft a reply to jane@x.com"), so redaction keeps the request useful while keeping data from the third-party provider. A secret in a prompt has no legitimate use for the model, and sending it out is a credential exposure - block and alert.

**Q: Why Luhn for credit cards?**
A 16-digit regex matches order numbers, phone strings, IDs. Luhn is the checksum all real card numbers satisfy; it removes ~90% of random false positives at negligible cost.

**Q: Why hash prompts in the audit log?**
The audit log would otherwise become a second copy of every sensitive prompt - a new data store to protect, retain, and disclose. A hash still lets you correlate repeated prompts and prove what was sent if you have the original. Limitation: short prompts can be brute-forced, so a keyed HMAC is the better production choice.

**Q: How does the canary work and what does it miss?**
A random marker is placed only in the system prompt. If the response contains it, the model must have copied its instructions. It misses paraphrased leakage - the model could summarize its instructions without the token.

**Q: How would you scale this?**
Stateless app behind a load balancer; move rate-limit state to Redis; ship audit logs to a SIEM (Splunk, Sentinel, CloudWatch) instead of a local file; store keys in a secrets manager with rotation; add streaming support with chunked output scanning.

**Q: How does this map to frameworks?**
OWASP LLM01 (injection), LLM02 (sensitive disclosure), LLM07 (system prompt leakage), LLM10 (unbounded consumption) are the main ones. For NIST AI RMF: policy YAML supports Govern, the usage report supports Map, the evaluation script supports Measure, and runtime blocking/logging supports Manage. Details in CONTROL_MAPPING.md.

**Q: Why are system messages trusted?**
They are set by the application owner, not the end user. Scanning them would flag legitimate instructions like "You are a support agent". The risk is indirect injection, where untrusted content (web pages, documents) is inserted into the prompt; apps should put such content in user-role messages so it gets scanned.

**Q: What would you build next?**
ML classifier layer, streaming support, Redis rate limiting, HMAC-keyed prompt hashes, per-team PII policies (e.g. allow emails for support), SIEM export, and an admin API for key rotation.
