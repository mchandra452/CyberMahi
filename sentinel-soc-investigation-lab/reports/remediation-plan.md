# Remediation Plan

## Immediate
1. Reset affected user password.
2. Revoke active sessions/tokens.
3. Validate MFA configuration and enforce strong method.

## Short-Term
1. Audit mailbox forwarding/inbox rules.
2. Block sender/domain/URL indicators where appropriate.
3. Increase monitoring for repeat sign-ins from suspicious IP/location.

## Longer-Term
1. Tune analytic rules for failure burst + success correlation.
2. Run targeted phishing awareness session.
3. Review conditional access coverage for high-risk sign-ins.
