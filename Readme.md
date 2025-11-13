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

