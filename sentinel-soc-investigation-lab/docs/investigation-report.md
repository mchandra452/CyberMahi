# Investigation report guide

`python -m soclab analyze` and `python -m soclab build-report` write the current run to `artifacts/latest/`. After verification, maintainers copy the complete deterministic set to `artifacts/example/`; CI regenerates `latest/` and requires byte-for-byte parity with that committed example. The authoritative committed report is [`artifacts/example/investigation-report.md`](../artifacts/example/investigation-report.md).

The report consumes the selected incident findings, event chronology, metrics, lab configuration, and linked rule metadata. An unrelated accepted false positive can affect regression precision without appearing in the incident evidence or timeline.

Required sections cover executive summary, classification, confidence, all affected entity types, event chronology, linked evidence, hypotheses, benign alternatives, evidence-qualified ATT&CK assessments, containment, recovery, gaps, verdict, and limitations. Analysts should preserve uncertainty and replace synthetic values only with authorised evidence from their own lab.
