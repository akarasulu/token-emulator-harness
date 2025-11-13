# Universal Token Emulator / Test Harness

## Overview
This project provides a unified emulator stack to support strong authentication
and authorization testing across multiple protocols and token types, including:

- PKCS#11 token emulation
- FIDO2 / WebAuthn / CTAP2 authenticator emulation
- TOTP / HOTP / OCRA token emulation
- Smart-card / CCID token emulation
- Client-certificate (mutual TLS) flows
- Mobile authenticator (BLE/NFC) emulation
- Remote HSM / KMIP token emulation

## Getting Started

### Prerequisites

- Docker & Docker Compose
- Python 3.10+
- Linux (required for virtual USB/CCID support)

### Setup

```bash
./docker/scripts/start_emulator.sh
```

### Dev Container

For a ready-to-use VS Code Dev Container / GitHub Codespaces environment,
launch the repo using the configuration under `.devcontainer/`. The container
image ships with Python 3.11 and installs `requirements-dev.txt`, so you can run
`pytest src/tests` immediately.  
The dev container also mounts the host Docker socket (via the
`docker-outside-of-docker` feature) so you can run harness commands inside the
container, for example:

```bash
# from repo root inside the dev container
docker compose -f docker/docker-compose.yml up --build
docker compose -f docker/docker-compose.yml down -v
```

### Usage

Use the control API to:

- `POST /reset_all` — reset all emulator modules
- `POST /otp/seed` + `GET /otp/code/{seed_id}` — manage TOTP/HOTP/OCRA seeds
- `POST /pkcs11/keys` / `GET /pkcs11/keys` — simulate PKCS#11 key lifecycle
- `POST /fido2/register` / `POST /fido2/authenticate` — emulate FIDO2 flows
- `POST /smartcard/insert` / `POST /smartcard/remove` / `GET /smartcard/status`
- `POST /mobile/pair` / `POST /mobile/assert` — BLE/NFC mobile authenticators
- `POST /network_hsm/sign` — sign payloads via the HSM emulator
- `POST /issue_ocra_challenge` — issue OCRA challenges
- `GET /openapi.yaml` — download the OpenAPI definition
- `GET /docs` — view a built-in preview

Run the API locally without Docker:

```bash
PYTHONPATH=src python -m control_api.main
```

### Configuration

Modify `config/emulator_config.yaml` to adjust module paths, PINs, seed drift
windows, authenticator IDs, etc.

## Running Tests

```bash
pytest
```

## CI Integration

The `.github/workflows/main.yml` workflow (to be fleshed out) will build the
emulator stack, run tests, collect logs, and tear down services.

## Extending the Harness

Modules live in `src/`. To add support for a new protocol or transport:

1. Add a new sub-folder (e.g., `src/mobile_emulator/`)
2. Define CLI/control API hooks for that module
3. Add tests under `src/tests/`
4. Update `docs/SPEC.md` and `docs/ARCHITECTURE.md`

## Local Harness via Docker

```bash
docker compose -f docker/docker-compose.yml up --build
# interact with the API (port 8080)...
docker compose -f docker/docker-compose.yml down -v
```

## OpenAPI Spec

- Source file: `docs/openapi.yaml`
- Served directly from the harness at `/openapi.yaml` (YAML) and `/docs` (HTML preview)
- Export for publishing via:

```bash
./scripts/export_openapi.sh
# outputs dist/openapi.yaml
```

## License

MIT
