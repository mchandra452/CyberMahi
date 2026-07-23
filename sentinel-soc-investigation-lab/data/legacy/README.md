# Legacy data migration

The earlier project used three CSV fixtures for sign-ins, email, and a condensed incident timeline. They were reviewed during migration but intentionally not retained in the active tree: they contained non-documentation public IP addresses, `.local` names, and a shallower single-alert scenario. Their useful fields and failure-to-success sequence were rebuilt as safe, typed JSON Lines records in `data/telemetry/`; Git history retains the original CSVs for provenance.
