# Codex Agent Guide

Welcome! This document explains how to work inside the `token-emulator-harness`
repository when using Codex or other automation agents.

## Project Overview

The goal of this repo is to build a universal token/emulator harness capable of
simulating PKCS#11 tokens, FIDO2/CTAP2 authenticators, TOTP/HOTP/OCRA generators,
smart-card/CCID devices, mutual-TLS client cert tokens, mobile (BLE/NFC)
authenticators, OpenPGP/GPG cryptographic operations, and remote HSM/KMIP services.
The current codebase contains scaffolding (control API, Docker stack, docs, tests,
and a terminal-based UI) that we extend over time.

## Environment & Tooling

- Preferred Python version: **3.11** (matches dev container / runtime)
- Container runtime: **Docker 24+** with **docker-compose**
- Testing framework: **pytest**
- Primary entry script: `docker/scripts/start_emulator.sh`
- Control API entry point: `src/control_api/main.py` (custom lightweight server)
- Terminal UI entry point: `src/tui/__main__.py` (Textual-based TUI)
- WebAuthn bridge assets live under `assets/` and are served at `/bridge/webauthn.js`

When running shell commands, execute them from the repo root unless a different
`workdir` is specified.

## Setup Steps

1. `python3 -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt && pip install -r requirements-dev.txt`
3. `docker compose -f docker/docker-compose.yml up --build` (or run `PYTHONPATH=src python -m control_api.main`)
4. Run tests with `pytest`

## Coding Guidelines

- Keep code Pythonic and modular. Place protocol-specific logic under the
  corresponding submodule in `src/`.
- Prefer explicit typing (type hints) for new Python code.
- Document new endpoints and module behavior in `docs/ARCHITECTURE.md` and
  `docs/SPEC.md`.
- Update configuration defaults in `config/emulator_config.yaml` when adding new
  knobs.
- For control API changes, add/extend tests in `src/tests/`.

## Key Modules

### PGP/OpenPGP Emulator (`src/harness/services.py::PGPService`)
The PGP emulator provides basic OpenPGP cryptographic operations without requiring
external GPG installations:
- Generate PGP key pairs (in-memory, with configurable name/email)
- Sign messages with PGP keys
- Encrypt/decrypt messages using a simple symmetric stream cipher
- List all generated keys by fingerprint and UIDs

Control API endpoints:
- `GET /pgp/keys` — list all PGP keys
- `POST /pgp/keys` — generate a new PGP key pair
- `POST /pgp/sign` — sign a message with a specified fingerprint
- `POST /pgp/encrypt` — encrypt a message for a recipient fingerprint
- `POST /pgp/decrypt` — decrypt a PGP-encrypted message

Configuration: Set default name and email in `config/emulator_config.yaml` under
the `pgp` section.

### Terminal UI (`src/tui/`)
A Textual-based terminal user interface for interacting with the harness without
manually crafting HTTP requests. Features include:
- Multi-tabbed interface for different emulator types (OTP, PKCS#11, FIDO2,
  Smart Card, Mobile, HSM, PGP)
- Real-time status displays and interactive controls
- Built-in server launcher (auto-starts control API if not running)
- Form inputs for common operations (generate keys, issue seeds, etc.)

To run: `PYTHONPATH=src python -m tui`

The TUI automatically discovers the control API at `http://127.0.0.1:8080` or via
the `HARNESS_BASE_URL` environment variable.

## Definition of Done

- Code compiles/lints and pytest suite passes.
- Docker services build successfully.
- README + docs updated if behavior changes.
- Relevant configuration entries and tests added.

## Useful Commands

```bash
# Start stack
docker compose -f docker/docker-compose.yml up -d

# Reset state (placeholder)
docker/scripts/reset_all.sh

# Run control API locally
PYTHONPATH=src python -m control_api.main

# Run TUI (Terminal UI) locally
PYTHONPATH=src python -m tui

# Run tests
pytest -q

# Export OpenAPI spec
./scripts/export_openapi.sh  # -> dist/openapi.yaml
```

## Open Tasks / Wish List

- Flesh out each emulator module (PKCS#11, FIDO2, TOTP, smart-card, mobile,
  network HSM, OpenPGP/GPG).
- Implement real control API handlers and orchestration layer.
- Add integration tests that exercise Dockerized services end-to-end.
- Expand CI to run dockerized tests and archive logs.
- Enhance TUI with additional views and real-time monitoring capabilities.

Please keep this file up to date whenever you add new workflows or expectations.
