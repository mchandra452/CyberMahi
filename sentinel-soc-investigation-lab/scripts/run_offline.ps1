$ErrorActionPreference = 'Stop'
python -m soclab validate
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m soclab analyze
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m soclab test-detections
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python -m soclab build-report
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
pytest
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
