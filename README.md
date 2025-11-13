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
- OpenSSL CLI (used for WebAuthn key generation)

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
- `GET /bridge/webauthn.js` — inject the FIDO2/WebAuthn bridge script for manual browser testing
- `POST /bridge/register` / `POST /bridge/authenticate` — harness endpoints used by the bridge
- `GET /pgp/keys` / `POST /pgp/keys` — list or generate OpenPGP keys
- `POST /pgp/sign`, `/pgp/encrypt`, `/pgp/decrypt` — sign, encrypt, or decrypt messages with the PGP emulator

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

## Manual FIDO2 Testing (Browser Bridge)

1. Start the harness locally (Python or Docker).
2. In the browser tab pointing at the FIDO2-enabled site, execute:

   ```javascript
   (function () {
     window.__TOKEN_HARNESS_URL = "http://localhost:8080";
     const s = document.createElement("script");
     s.src = "http://localhost:8080/bridge/webauthn.js";
     document.head.appendChild(s);
   })();
   ```

    This overrides `navigator.credentials.create/get` so WebAuthn calls are routed to the harness via `/bridge/register` and `/bridge/authenticate`.
3. Trigger registration / authentication flows as usual. The harness generates valid attestation/assertion responses (ES256, packed/self attestation) and returns them to the page via the injected script.
4. To revert, refresh the page (restoring the browser’s native authenticator).

### Bookmarklet

Create a new bookmark with the following URL (update the host/port if your harness runs elsewhere):

```javascript
javascript:(function(){window.__TOKEN_HARNESS_URL='http://localhost:8080';const s=document.createElement('script');s.src='http://localhost:8080/bridge/webauthn.js';document.head.appendChild(s);}());
```

Clicking the bookmark while on a target site injects the bridge automatically—no console needed. You can also fetch the raw script from `http://localhost:8080/bridge/webauthn.js` and include it in extensions or other automation.

## PGP Workflows

The harness includes a software PGP emulator (deterministic RSA-like behavior with ASCII armor). Sample usage:

```bash
# create a new test key
curl -sS -X POST http://localhost:8080/pgp/keys \
     -H 'Content-Type: application/json' \
     -d '{"name":"Harness Tester","email":"tester@example.com"}'

# sign data (detached, ASCII armored)
curl -sS -X POST http://localhost:8080/pgp/sign \
     -H 'Content-Type: application/json' \
     -d '{"fingerprint":"<FPR>","message":"hello"}'

# encrypt + decrypt
curl -sS -X POST http://localhost:8080/pgp/encrypt \
     -H 'Content-Type: application/json' \
     -d '{"fingerprint":"<FPR>","message":"secret"}'
curl -sS -X POST http://localhost:8080/pgp/decrypt \
     -H 'Content-Type: application/json' \
     -d '{"fingerprint":"<FPR>","ciphertext":"-----BEGIN PGP MESSAGE-----..."}'
```

Responses are ASCII armored blocks (for signatures/ciphertext) or plaintext strings, so they can be dropped directly into other tooling.

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
