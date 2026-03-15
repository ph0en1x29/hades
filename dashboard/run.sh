#!/usr/bin/env bash
# Hades Dashboard — zero-dependency Node.js server
set -euo pipefail
cd "$(dirname "$0")"
echo "Starting Hades Dashboard on http://localhost:8666"
exec node server.js
