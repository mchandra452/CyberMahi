# MITRE ATT&CK Mapping

This mapping is evidence-based and avoids overclaiming.

## T1566 - Phishing
Applicable. User-reported suspicious email with fake Microsoft 365 login theme suggests phishing intent.

## T1110 - Brute Force
Potentially applicable. Repeated failed authentication attempts indicate possible password guessing activity.

## T1078 - Valid Accounts
Applicable as a likely outcome. A successful login after repeated failures may indicate use of compromised valid credentials.

## T1539 - Steal Web Session Cookie
Not confirmed. Included only as a risk consideration if session hijack artefacts appear in extended telemetry.

## T1589 - Gather Victim Identity Information
Possible pre-attack activity. Could apply if adversary profiled target users for believable phishing themes.

## T1087 - Account Discovery
Possible follow-on behaviour. Not directly evidenced in current dataset but relevant if suspicious directory/account enumeration appears later.
