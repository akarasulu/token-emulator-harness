#!/usr/bin/env bash
set -e

REPO_ROOT="${1:-token-emulator-harness}"
echo "Creating repository skeleton at: $REPO_ROOT"

mkdir -p "$REPO_ROOT"
cd "$REPO_ROOT"

# Create folder structure
mkdir -p docker/scripts
mkdir -p src/control_api
mkdir -p src/pkcs11_emulator
mkdir -p src/fido2_emulator
mkdir -p src/totp_emulator
mkdir -p src/smartcard_emulator
mkdir -p src/tests
mkdir -p docs
mkdir -p ci/.github/workflows
mkdir -p ci/scripts
mkdir -p config

# Create files
cat > README.md << 'EOF'
# Universal Token Emulator / Test Harness

## Overview
This repository hosts a unified emulator stack for strong authentication and test flows including PKCS#11, FIDO2/WebAuthn, TOTP/HOTP, smart-card tokens, and more.

## Getting Started
1. Ensure you have Docker, Docker Compose, and Python 3.10+.
2. Run `docker/docker-compose.yml` to spin up the emulator stack.
3. Use the control API to reset state, issue TOTP seeds, simulate user presence, etc.

## CI
The `.github/workflows/main.yml` contains the CI configuration to build and test the harness.

## Contributing
See `docs/` for detailed architecture and spec.

## License
MIT
EOF

cat > docker/Dockerfile << 'EOF'
# TODO: fill in base image and setup for emulator stack
FROM ubuntu:24.04
WORKDIR /opt/emulator
# Install dependencies…
EOF

cat > docker/docker-compose.yml << 'EOF'
version: "3.8"
services:
  control_api:
    build:
      context: ./docker
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    volumes:
      - ./config:/opt/emulator/config
      - ./logs:/opt/emulator/logs
    # Add other emulator sub-services here
EOF

cat > docker/scripts/start_emulator.sh << 'EOF'
#!/usr/bin/env bash
echo "Starting emulator stack..."
docker-compose -f ../docker-compose.yml up -d
EOF
chmod +x docker/scripts/start_emulator.sh

cat > docker/scripts/reset_all.sh << 'EOF'
#!/usr/bin/env bash
echo "Resetting emulator state..."
# TODO: call control API endpoint /reset_all or clean volumes
EOF
chmod +x docker/scripts/reset_all.sh

cat > src/control_api/main.py << 'EOF'
"""
Control API for the Token Emulator Harness
"""
from fastapi import FastAPI

app = FastAPI()

@app.post("/reset_all")
async def reset_all():
    return {"status": "reset triggered"}

@app.post("/issue_seed")
async def issue_seed(type: str):
    return {"seed": "PLACEHOLDER_FOR_"+type.upper()}
EOF

cat > config/emulator_config.yaml << 'EOF'
# Default configuration for emulator harness
pkcs11:
  module_path: "/opt/emulator/lib/pkcs11.so"
  slot_index: 0
  user_pin: "1234"
fido2:
  authenticator_id: "emu1"
totp:
  drift_window: 30
EOF

cat > src/tests/test_pkcs11.py << 'EOF'
def test_pkcs11_placeholder():
    assert True  # TODO: implement PKCS#11 emulator tests
EOF

cat > src/tests/test_fido2.py << 'EOF'
def test_fido2_placeholder():
    assert True  # TODO: implement FIDO2 emulator tests
EOF

cat > src/tests/test_totp.py << 'EOF'
def test_totp_placeholder():
    assert True  # TODO: implement TOTP emulator tests
EOF

cat > src/tests/test_smartcard.py << 'EOF'
def test_smartcard_placeholder():
    assert True  # TODO: implement smart-card emulator tests
EOF

cat > docs/SPEC.md << 'EOF'
# Specification Document

(Insert detailed spec for universal token emulator/test harness…)
EOF

cat > docs/ARCHITECTURE.md << 'EOF'
# Architecture & Design

(Insert architecture discussion for modular emulator stack…)
EOF

cat > ci/.github/workflows/main.yml << 'EOF'
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build Docker Emulator Stack
        run: docker-compose -f docker/docker-compose.yml up -d
      - name: Wait for services
        run: sleep 15
      - name: Run tests
        run: pytest --maxfail=1 --disable-warnings -q
      - name: Teardown
        run: docker-compose -f docker/docker-compose.yml down --volumes --remove-orphans
EOF

cat > ci/scripts/ci_setup.sh << 'EOF'
#!/usr/bin/env bash
echo "Setting up CI environment for emulator stack..."
# TODO: install prerequisites, start services if needed
EOF
chmod +x ci/scripts/ci_setup.sh

cat > .gitignore << 'EOF'
__pycache__/
*.pyc
docker/logs/
logs/
EOF

echo "Repository skeleton created."

