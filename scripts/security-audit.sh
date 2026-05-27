#!/usr/bin/env bash
set -euo pipefail
python -m pip_audit -r requirements.txt \
  --ignore-vuln GHSA-gc5v-m9x4-r6x2 \
  --ignore-vuln PYSEC-2024-277
python -m bandit -q -r app
python -m ruff check .
python -m pytest -q
