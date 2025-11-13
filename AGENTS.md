# Codex Agent Guide

Welcome! This document explains how to work inside the `token-emulator-harness`
repository when using Codex or other automation agents.

## Project Overview

The goal of this repo is to build a universal token/emulator harness capable of
simulating PKCS#11 tokens, FIDO2/CTAP2 authenticators, TOTP/HOTP/OCRA generators,
smart-card/CCID devices, mutual-TLS client cert tokens, mobile (BLE/NFC)
authenticators, and remote HSM/KMIP services. The current codebase contains
scaffolding (control API, Docker stack, docs, tests) that we extend over time.

## Environment & Tooling

- Preferred Python version: **3.11** (matches dev container / runtime)
- Container runtime: **Docker 24+** with **docker-compose**
- Testing framework: **pytest**
- Primary entry script: `docker/scripts/start_emulator.sh`
- Control API prototype: `src/control_api/main.py` (FastAPI)

When running shell commands, execute them from the repo root unless a different
`workdir` is specified.

## Setup Steps

1. `python3 -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt` (to be added later; for now install FastAPI + uvicorn manually if needed)
3. `docker compose -f docker/docker-compose.yml up --build` (or run `uvicorn` locally)
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
uvicorn src.control_api.main:app --reload --port 8080

# Run tests
pytest -q
```

## Open Tasks / Wish List

- Flesh out each emulator module (PKCS#11, FIDO2, TOTP, smart-card, mobile,
  network HSM).
- Implement real control API handlers and orchestration layer.
- Add integration tests that exercise Dockerized services end-to-end.
- Expand CI to run dockerized tests and archive logs.

Please keep this file up to date whenever you add new workflows or expectations.
