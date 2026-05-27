#!/usr/bin/env bash
set -euo pipefail
python -m pip_audit -r requirements.txt
python -m bandit -q -r app
python -m ruff check .
python -m pytest -q
