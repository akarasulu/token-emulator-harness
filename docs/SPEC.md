# Specification Document

## Scope & Modules

The Universal Token Emulator / Test Harness aims to cover the following
protocols, transports, and token styles:

- PKCS#11 token slot emulation
- FIDO2 / CTAP2 / WebAuthn roaming and platform authenticators
- TOTP / HOTP / OCRA seed issuance and code generation
- Smart-card (ISO 7816 / PC/SC / CCID) emulation
- Client certificate / mutual TLS token flows
- Mobile authenticator (BLE/NFC) emulation
- Remote HSM / KMIP-style network token emulation

## Requirements (High Level)

1. Provide a control API for orchestration (resetting modules, issuing seeds,
   registering/authenticating credentials, inserting cards, mobile pairing, HSM
   operations, etc). Implemented via FastAPI in `src/control_api/main.py`.
2. Offer deterministic + randomized modes for reproducible CI testing (current
   in-memory design seeds random values per request; deterministic hooks can be
   added via configuration overrides).
3. Support modular enablement so tests can target specific protocols.
4. Supply logging and telemetry for each module for debugging (TBD).
5. Run headless inside containers/CI environments (docker-compose stack + dev
   container provide this).
