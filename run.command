#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON="$VENV_DIR/bin/python"

cd "$SCRIPT_DIR"

if [[ ! -x "$PYTHON" ]]; then
    if command -v uv >/dev/null 2>&1; then
        uv venv "$VENV_DIR" --python 3.12
    else
        python3 -m venv "$VENV_DIR"
    fi
fi

if ! "$PYTHON" -c 'import tkinter' >/dev/null 2>&1; then
    print -u2 "The Python environment at $VENV_DIR does not include Tk (_tkinter)."
    print -u2 "Install a Tk-enabled Python, remove .venv, and run this command again."
    exit 1
fi

exec "$PYTHON" "$SCRIPT_DIR/path_safety_scanner.py" "$@"
