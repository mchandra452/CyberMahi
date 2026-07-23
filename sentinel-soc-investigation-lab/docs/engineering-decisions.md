# Engineering decisions

## JSON Lines rather than CSV

JSON Lines preserves typed arrays and source-specific fields while remaining diffable and streamable. Stable event IDs and one record per line simplify deterministic fixtures. CSV would require lossy encoding for scopes, entities, and nested consent details.

The previous CSV fixtures were reviewed rather than copied forward. They contained public IP examples outside the documentation ranges and no longer matched the multi-source scenario. Useful authentication, delivery, risk, and timeline concepts were re-expressed in the safe JSON Lines model; the old files remain recoverable from Git history.

## Python equivalents rather than a KQL emulator

The offline engine validates behavioural intent, labels, metrics, duplicate handling, and outputs. Implementing a partial KQL interpreter would create false confidence. Native KQL still requires execution against real tables in the Defender portal.

## Static baselines

Static baselines make regression results repeatable and explainable. They cannot represent seasonality, organisational change, or long-tail user behaviour. Production baselines must include age, population segmentation, data-quality monitoring, and review ownership.

## Native tables with ASIM notes

Native table names make connector requirements explicit. ASIM is noted where practical, especially authentication, but not forced without confirming parser field fidelity and query performance in a live workspace.

## Simulated OAuth and endpoint evidence

OAuth scopes, identifiers, process text, and hashes are fictional. The PowerShell command is inert and redacted. This preserves investigative structure without providing an operational payload or implying tenant access.

## Risk fusion

Weights are configuration, not hidden code. One contribution per detection ID prevents duplicates from inflating risk. Four categories are required; high confidence needs wider independent coverage. The model is illustrative and must not drive automatic containment.

## Rejected ATT&CK mappings

No token-theft mapping is attached to consent because consent does not establish token abuse. No technique is mapped to domain novelty because novelty is context, not attacker behaviour. T1530 remains inferred because download volume does not establish malicious intent or exfiltration.
