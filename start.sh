#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "========================================"
echo "  Detector - Phishing URL Analyzer"
echo "========================================"

VENV_DIR="$PROJECT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

echo "[*] Activating virtual environment..."
source "$VENV_DIR/bin/activate"

echo "[*] Installing dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo "[*] Ensuring results directory exists..."
mkdir -p results instance

echo "[*] Starting Flask application..."
echo "    Open http://127.0.0.1:5000 in your browser"
echo "========================================"
echo ""

export FLASK_ENV=${FLASK_ENV:-development}
export FLASK_APP=run.py

python run.py
