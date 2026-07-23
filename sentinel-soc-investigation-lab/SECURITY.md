# Security policy

## Defensive scope

This repository contains defensive detection logic and inert synthetic evidence. It must not contain exploit code, working payloads, real victim data, credentials, active infrastructure, or instructions for attacking systems.

Use only reserved domains and documentation IP ranges. Suspicious command strings must remain redacted and non-operational. Do not deploy response automation without security, legal, operational, and change-control review.

## Reporting accidental exposure

If a secret, real identifier, or sensitive record is committed, stop using it, notify the repository owner through a private approved channel, revoke or rotate the value at its source, preserve only necessary audit evidence, and remove it following the hosting provider's sensitive-data procedure. Do not paste the value into an issue or log; identify only the affected path and commit.

For ordinary defensive defects, open an issue with synthetic reproduction data. Security reports should state affected version, impact, reproduction boundary, and safe remediation guidance.
