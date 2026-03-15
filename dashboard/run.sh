#!/usr/bin/env bash
# Hades Dashboard — one-command start
# Usage: bash run.sh
# Then open: http://localhost:8666

set -e
cd "$(dirname "$0")"

echo "▶ Installing Python deps..."
pip install -q fastapi "uvicorn[standard]" python-multipart websockets aiofiles

echo "▶ Starting Hades Dashboard on http://0.0.0.0:8666"
echo "   Open: http://localhost:8666"
echo ""
python3 -m uvicorn app:app --host 0.0.0.0 --port 8666 --reload
