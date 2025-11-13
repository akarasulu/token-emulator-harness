#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${ROOT_DIR}/dist"

mkdir -p "${OUTPUT_DIR}"
cp "${ROOT_DIR}/docs/openapi.yaml" "${OUTPUT_DIR}/openapi.yaml"

echo "OpenAPI spec copied to ${OUTPUT_DIR}/openapi.yaml"
