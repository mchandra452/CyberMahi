# False Positive Handling

## Common False Positive Sources
- Corporate VPN exit nodes causing country anomalies.
- Legitimate travel or remote workforce movement.
- User typo bursts during password changes.
- Internal phishing simulations.

## L1 Analyst Handling Steps
1. Verify whether IP belongs to known corporate/VPN ranges.
2. Check user travel context or approved remote-access notes.
3. Compare behaviour to 14-30 day baseline.
4. Confirm whether security awareness simulation was active.
5. Document why alert is closed/tuned and what rule change is proposed.

## Tuning Actions
- Add validated VPN IP exceptions.
- Increase failure threshold for high-noise accounts.
- Correlate only when 2+ suspicious signals occur.
