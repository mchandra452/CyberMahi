# AgentShield — Evaluation and engineering limitations

## Hypothesis

A local, deterministic substring baseline can flag selected **known phrases** for a security-operations demonstration. It is not a general-purpose prompt-injection detector and has no ability to enforce tool-use policy.

## Current evidence

- The CLI loads phrase rules from `detection/detection_rules.json`.
- `analyze_prompt()` normalises input and performs string containment checks.
- Known synthetic attack-like phrases generate rule IDs and fixed risk labels.
- A benign example produces no matching alert.
- Privacy tests require emitted alert objects, JSONL files and captured file-mode output to exclude a distinctive input-only marker.
- CI executes `python -m unittest discover -s tests`.

These checks establish basic deterministic behaviour, not accuracy in real-world AI agents.

## Reproducible follow-up experiments — not yet completed

| Hypothesis/test | Fixture | Evidence to capture |
| --- | --- | --- |
| Benign quotation causes a false positive | Neutral text quoting a trigger phrase | FP count and exact pattern |
| Paraphrasing misses a malicious attempt | Reworded synthetic instruction override | FN count and missed rule |
| Obfuscation bypasses matching | Altered separators/encoding | Detection outcome |
| Language coverage is limited | Equivalent synthetic non-English phrase | FN result |
| Real agent boundary differs from phrase matching | Mock retrieved document and mock tool-call gate | Tool decisions, deny/audit logs |
| Logs preserve data minimisation | Detectable synthetic prompt with unique marker | Alert JSONL and stdout free of original marker |

For a labelled corpus, compute TP, FP, FN, TN, precision and recall. Publish specific misclassifications alongside aggregate numbers. Do not generalise demo-corpus measurements to real production models.

## Security design notes

- Prior versions stored the full source prompt in the `input_sample` alert field. New alerts retain only `[REDACTED]`, input length and rule metadata. **Previously created local log files are not automatically scrubbed.**
- The tool still receives raw input, and interactive shell or file contents can expose sensitive text. Only synthetic non-sensitive examples should be tested.
- Keyword/substring detection does not account for intent, semantic context, multi-turn attacks or untrusted retrieval.
- The optional dashboard is a local visualisation, not an authenticated SOC deployment.
- Risk scores are static rule labels without calibration.
- The retired nested prototype's sample defensive controls were not connected to the active CLI and are not represented as protections.

## Recommended next engineering milestone

Implement a **mock tool-call permission gate** that separately checks allowed tools, parameters and resource scope, with unit tests for permitted and rejected calls. Measure failures against a labelled synthetic corpus before experimenting with real LLM traffic.
