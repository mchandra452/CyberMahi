# OWASP LLM Security Mapping

This document maps the lab’s scenarios and controls to the OWASP Top 10 risks for large language models.

| Lab Area | Related OWASP LLM Risk | Description |
|---|---|---|
| Prompt Injection | LLM01: Prompt Injection | Tests crafted prompts that attempt to override instructions |
| Output Filtering | LLM02: Insecure Output Handling | Validates and filters unsafe model outputs |
| Token Flooding | LLM04: Model Denial of Service | Simulates excessive or resource-heavy input |
| Secret Extraction | LLM06: Sensitive Information Disclosure | Detects attempts to reveal secrets or hidden context |
| Tool Abuse | LLM07: Insecure Plugin Design | Tests unsafe tool or plugin invocation |
| Agent Autonomy | LLM08: Excessive Agency | Demonstrates risks from uncontrolled agent actions |
