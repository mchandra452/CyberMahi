# Detection catalog

| ID | Name | Signal source | Severity | Confidence | ATT&CK | Output entities | Offline status |
|---|---|---|---|---|---|---|---|
| DET001 | Password Spray Across Cloud Accounts | Entra sign-ins | Medium | High | T1110.003 observed | Account, IP | Required case passes |
| DET002 | Successful Authentication After Failure Burst | Entra sign-ins | High | High | T1078.004 inferred | Account, IP | Required case passes |
| DET003 | Unusual Authentication Context | Entra + baseline | Medium | Medium | T1078.004 inferred | Account, IP, host | VPN control suppressed |
| DET004 | Phishing-Link Indicators | Email + URL | Medium | High | T1566.002 observed | Account, URL, domain | Required case passes |
| DET005 | Suspicious OAuth Consent | Entra audit | High | Medium | T1098.003 inferred; no token-theft claim | Account, app ID/name, IP | Admin control suppressed |
| DET006 | External Mail Forwarding Rule | Exchange audit | High | High | T1114.003 observed | Account, mailbox, IP | Required case passes |
| DET007 | Cloud Download Anomaly | M365 audit + baseline | Medium | Medium | T1530 inferred | Account, IP | Backup control suppressed |
| DET008 | Office Application Spawning PowerShell | Endpoint process | High | High | T1059.001 observed | Host, account, process | Required case passes |
| DET009 | New or Rare Domain DNS Activity | Endpoint network | Low | Medium | Not mapped; novelty is not a technique | Host, account, domain | One accepted benign FP |
| DET010 | Identity-Led Incident Fusion | Sentinel alerts | High | High | Not mapped; fusion is an analytic mechanism | Account, IP, host, app ID/name, domain, URL, mailbox, process | Required fusion passes |

ATT&CK confidence is carried in rule metadata with supporting evidence and required follow-up. DET005 cautiously infers account manipulation from the consent grant; the fixture does not show token theft, token use, or application abuse. DET009 and DET010 retain explicit `not_mapped` assessments because their telemetry does not support a precise technique.

Each rule metadata file justifies severity and confidence and binds one malicious and one benign case to stable telemetry event IDs. These statuses describe Python-equivalent synthetic regression only; the KQL has not been executed in Microsoft Sentinel.
