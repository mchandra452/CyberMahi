#!/usr/bin/env sh
set -eu
python -m soclab validate
python -m soclab analyze
python -m soclab test-detections
python -m soclab build-report
pytest
