#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8080}"

echo "Resetting emulator state via ${API_URL}/reset_all"
curl -sSf -X POST "${API_URL}/reset_all" >/dev/null
echo "Reset request sent."
