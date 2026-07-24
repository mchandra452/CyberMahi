#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
VENV_DIR="$PROJECT_ROOT/.venv"

if [ -n "${PYTHON:-}" ]; then
    BOOTSTRAP_PYTHON=$PYTHON
elif command -v python3 >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    BOOTSTRAP_PYTHON=python
else
    echo "Python 3.11 or newer was not found. Install Python, then rerun this script." >&2
    exit 1
fi

cd "$PROJECT_ROOT"
"$BOOTSTRAP_PYTHON" -c "import sys; print(f'Using Python {sys.version.split()[0]}'); raise SystemExit(0 if sys.version_info >= (3, 11) else 'Python 3.11 or newer is required')"

if [ ! -x "$VENV_DIR/bin/python" ] && [ ! -x "$VENV_DIR/Scripts/python.exe" ]; then
    echo "Creating isolated environment at .venv ..."
    "$BOOTSTRAP_PYTHON" -m venv "$VENV_DIR"
fi

if [ -x "$VENV_DIR/bin/python" ]; then
    VENV_PYTHON="$VENV_DIR/bin/python"
else
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
fi

echo "Installing the lab and development checks ..."
"$VENV_PYTHON" -m pip install -e '.[dev]'
"$VENV_PYTHON" -m soclab validate

echo "Setup complete. Run ./scripts/run_offline.sh to generate and verify the lab evidence."
