# Troubleshooting Guide

## Validator fails: missing files
- Ensure you are in `sentinel-soc-investigation-lab/`.
- Re-check filenames and paths (case-sensitive).

## Validator fails: CSV schema mismatch
- Confirm no header edits were made to files in `sample-logs/`.
- Compare columns with the expected schema in `tests/validate_lab.py`.

## Validator fails: CSV has too few rows
- Each CSV must contain at least 3 data rows (excluding header).

## KQL query returns no results in Sentinel
- Confirm table names match your connector schema.
- Adjust field names where your environment differs.
- Expand lookback windows (e.g., `ago(1d)` -> `ago(7d)`).

## Import issues with custom logs
- Confirm delimiter is comma and timestamps are ISO-8601 UTC.
- Validate row consistency and no malformed quotes.
