#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV_DIR="$PROJECT_ROOT/.venv"

if [ ! -x "$VENV_DIR/bin/python" ] && [ ! -x "$VENV_DIR/Scripts/python.exe" ]; then
    echo "No project environment found; running setup first ..."
    "$SCRIPT_DIR/setup.sh"
fi

if [ -x "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
else
    echo "Setup did not create .venv. Review the setup error and try again." >&2
    exit 1
fi

cd "$PROJECT_ROOT"
"$VENV_PYTHON" -m soclab validate
"$VENV_PYTHON" -m soclab analyze
"$VENV_PYTHON" -m soclab test-detections
"$VENV_PYTHON" -m soclab build-report
"$VENV_PYTHON" -m pytest

echo "PASS: offline workflow complete. Evidence is in artifacts/latest/."
