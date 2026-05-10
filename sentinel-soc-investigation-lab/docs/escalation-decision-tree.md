# Escalation Decision Tree (SOC L1)

1. **Is there phishing evidence for the user?**
   - No -> continue monitoring and gather more telemetry.
   - Yes -> proceed to step 2.

2. **Is there suspicious authentication activity?** (failure burst, unusual location, impossible travel)
   - No -> classify as suspicious email case, contain email indicators.
   - Yes -> proceed to step 3.

3. **Is there successful login after suspicious failures?**
   - No -> maintain heightened monitoring, tune thresholds.
   - Yes -> proceed to step 4.

4. **Any impact indicators?** (new mailbox rules, abnormal session activity)
   - No -> escalate as Medium-High suspected compromise.
   - Yes -> escalate as High and initiate containment immediately.

5. **Containment and handover**
   - Reset password, revoke sessions, verify MFA, document evidence and decisions.
