# Control Mapping

Maps gateway controls to the **OWASP Top 10 for LLM Applications (2025)** and the **NIST AI Risk Management Framework (AI RMF 1.0)** functions (Govern, Map, Measure, Manage). Coverage notes are honest: "partial" means the control reduces risk but does not eliminate it.

## OWASP Top 10 for LLM Applications (2025)

| OWASP ID | Risk | Gateway control | Code | Coverage |
|---|---|---|---|---|
| LLM01 | Prompt Injection | Scored heuristic rules (13), Unicode normalization, configurable block threshold | `gateway/guardrails/injection.py` | Partial - direct injection only; paraphrase and indirect injection can evade |
| LLM02 | Sensitive Information Disclosure | Input PII redaction; secret blocking (AWS keys, private keys); output PII redaction | `gateway/guardrails/pii.py`, `output.py` | Partial - pattern-based, US formats |
| LLM03 | Supply Chain | Model allow-list per team; pip-audit and bandit in CI; pinned dependency ranges | `gateway/policy.py`, `.github/workflows/ci.yml` | Partial |
| LLM05 | Improper Output Handling | Output scanned and sanitized before returning to caller | `gateway/guardrails/output.py` | Partial - no HTML/code sanitization |
| LLM06 | Excessive Agency | Gateway grants no tools; blocked-topic policy limits task scope | `gateway/policy.py` | Minimal - out of scope for a proxy |
| LLM07 | System Prompt Leakage | Canary token injected into system prompt; responses containing it are withheld | `gateway/main.py`, `output.py` | Partial - verbatim leakage only |
| LLM10 | Unbounded Consumption | Per-team max-token cap, per-client rate limiting, request size limits (100 messages, 100k chars) | `gateway/ratelimit.py`, `policy.py`, `main.py` | Good for single replica |
| LLM04 / LLM08 / LLM09 | Data poisoning, vector/embedding weakness, misinformation | Not addressed (training/RAG-layer concerns) | - | None |

## NIST AI RMF 1.0

| Function | Category (examples) | Gateway control |
|---|---|---|
| **Govern** | GV-1 policies and processes; GV-6 third-party risk | Policy-as-code in `config/policy.yaml` (who may use which model, for what); model allow-list governs third-party model use |
| **Map** | MP-4 risks of third-party components; MP-5 impacts | Shadow-AI visibility: audit log + `usage_report.py` show which teams use which models and how often |
| **Measure** | MS-2 evaluated for trustworthiness; MS-2.7 security and resilience; MS-3 tracking risks over time | `scripts/evaluate.py` reports precision/recall; CI enforces a quality floor; audit metrics (block rates, detections) tracked over time |
| **Manage** | MG-2 risk treatment; MG-3 third-party risk; MG-4 monitoring and response | Runtime blocking/redaction, rate limits, event IDs for incident triage, canary alerts for prompt leakage |

## Supporting security engineering controls

| Control | Implementation |
|---|---|
| Credential storage | API keys stored as SHA-256 digests; constant-time comparison |
| Privacy by design | Prompts hashed in audit log by default (`store_raw_prompts: false`) |
| Least privilege | Docker image runs as non-root `app` user |
| Secure SDLC | ruff (incl. flake8-bandit rules), bandit SAST, pip-audit SCA, pytest in CI |
| Fail closed | Upstream errors return 502; leaked output is withheld, not partially returned |
