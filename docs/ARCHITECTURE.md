# Architecture & Design

## High-Level Components

1. **Control API**
   - FastAPI service exposing operations such as reset, seed issuance,
     user-presence simulation, smart-card events, and mobile pairings.
2. **Module Layer**
   - Implemented in `src/harness/services.py` as in-memory simulators for
     PKCS#11, FIDO2, OTP, smart-card/CCID, mobile authenticator, and network
     HSM.
3. **Transport Layer**
   - Virtual USB HID, CCID, BLE, NFC, and network sockets emulate hardware
     transports. Modules may rely on existing open-source tools (e.g.,
     vsmartcard) or custom code.
4. **Test Harness Library**
   - Client helpers (initially Python) that call the control API and interact
     with each emulator to drive integration tests.
5. **Persistence & Logging**
   - Current implementation stores state in memory per process. Future work can
     back modules with persistent volumes (e.g., for CI log export).

## Design Principles

- Resettable & reproducible state between tests.
- Clear interfaces per module to allow swapping in real hardware.
- Minimal coupling so additional protocols can plug in later.
- CI-first workflow: automated startup, health checks, teardown.
