## Change

Describe the detection hypothesis, implementation, and evidence.

## Safety

- [ ] All data and indicators are synthetic and reserved.
- [ ] No credentials, tenant identifiers, victim data, payloads, or active infrastructure were added.
- [ ] Production and live-execution claims remain evidence-based.

## Verification

- [ ] `ruff check .`
- [ ] `pytest`
- [ ] `python -m soclab validate`
- [ ] `python -m soclab analyze`
- [ ] `python -m soclab test-detections`
- [ ] `python -m soclab build-report`
- [ ] Generated evidence and limitations were reviewed.
