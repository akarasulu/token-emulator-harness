#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Starting emulator stack from ${ROOT_DIR}/docker-compose.yml"
docker compose -f "${ROOT_DIR}/docker-compose.yml" up -d
