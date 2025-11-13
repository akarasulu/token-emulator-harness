"""Domain services that emulate token behavior in-memory."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional


_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def _random_secret(length: int = 32) -> str:
    return "".join(secrets.choice(_BASE32_ALPHABET) for _ in range(length))


def _timestamp() -> int:
    return int(time.time())


@dataclass
class OTPSeed:
    seed_id: str
    secret: str
    token_type: str = "totp"
    issued_at: int = field(default_factory=_timestamp)


@dataclass
class PKCS11Key:
    key_id: str
    label: str
    created_at: int = field(default_factory=_timestamp)
    material: str = field(default_factory=lambda: secrets.token_hex(32))


@dataclass
class FidoCredential:
    credential_id: str
    user_id: str
    rp_id: str
    public_key: str
    sign_count: int = 0


@dataclass
class SmartCardState:
    inserted: bool = False
    certificate: Optional[str] = None
    pin: str = "0000"


@dataclass
class MobileAuthenticatorState:
    device_id: str
    paired: bool = False
    last_challenge: Optional[str] = None


class OTPService:
    def __init__(self, drift_window: int = 30):
        self._seeds: Dict[str, OTPSeed] = {}
        self.drift_window = drift_window

    def reset(self) -> None:
        self._seeds.clear()

    def issue_seed(self, token_type: str = "totp") -> OTPSeed:
        seed = OTPSeed(seed_id=str(uuid.uuid4()), secret=_random_secret(), token_type=token_type)
        self._seeds[seed.seed_id] = seed
        return seed

    def current_code(self, seed_id: str, for_time: Optional[int] = None) -> str:
        seed = self._seeds.get(seed_id)
        if not seed:
            raise KeyError("unknown seed")
        timestamp = for_time or _timestamp()
        counter = int(timestamp // self.drift_window)
        key = base64.b32decode(seed.secret, casefold=True)
        msg = counter.to_bytes(8, "big")
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code_int = (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
        return f"{code_int:06d}"

    def issue_ocra_challenge(self) -> str:
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
        return challenge


class PKCS11Service:
    def __init__(self):
        self._keys: Dict[str, PKCS11Key] = {}

    def reset(self) -> None:
        self._keys.clear()

    def generate_key(self, label: str) -> PKCS11Key:
        key = PKCS11Key(key_id=str(uuid.uuid4()), label=label)
        self._keys[key.key_id] = key
        return key

    def list_keys(self) -> List[PKCS11Key]:
        return list(self._keys.values())


class FidoService:
    def __init__(self):
        self._credentials: Dict[str, FidoCredential] = {}

    def reset(self) -> None:
        self._credentials.clear()

    def register(self, user_id: str, rp_id: str) -> FidoCredential:
        cred = FidoCredential(
            credential_id=str(uuid.uuid4()),
            user_id=user_id,
            rp_id=rp_id,
            public_key=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        )
        self._credentials[cred.credential_id] = cred
        return cred

    def authenticate(self, credential_id: str, challenge: str) -> Dict[str, str | int]:
        cred = self._credentials.get(credential_id)
        if not cred:
            raise KeyError("unknown credential")
        cred.sign_count += 1
        signature_material = f"{challenge}:{cred.public_key}:{cred.sign_count}".encode("utf-8")
        signature = base64.urlsafe_b64encode(hashlib.sha256(signature_material).digest()).decode("ascii")
        return {
            "credential_id": cred.credential_id,
            "signature": signature,
            "sign_count": cred.sign_count,
        }


class SmartCardService:
    def __init__(self, default_pin: str = "0000"):
        self._state = SmartCardState(pin=default_pin)

    def reset(self) -> None:
        self._state = SmartCardState(pin=self._state.pin)

    def insert_card(self) -> SmartCardState:
        random_cert = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii")
        self._state.inserted = True
        self._state.certificate = f"CERT::{random_cert}"
        return self._state

    def remove_card(self) -> SmartCardState:
        self._state.inserted = False
        self._state.certificate = None
        return self._state

    def status(self) -> SmartCardState:
        return self._state


class MobileAuthenticatorService:
    def __init__(self):
        self._devices: Dict[str, MobileAuthenticatorState] = {}

    def reset(self) -> None:
        self._devices.clear()

    def pair(self, device_id: str) -> MobileAuthenticatorState:
        state = self._devices.get(device_id) or MobileAuthenticatorState(device_id=device_id)
        state.paired = True
        self._devices[device_id] = state
        return state

    def assert_challenge(self, device_id: str, challenge: str) -> Dict[str, str]:
        state = self._devices.get(device_id)
        if not state or not state.paired:
            raise KeyError("device not paired")
        state.last_challenge = challenge
        response_material = f"{device_id}:{challenge}".encode("utf-8")
        response = base64.urlsafe_b64encode(hashlib.sha1(response_material).digest()).decode("ascii")
        return {"device_id": device_id, "response": response}


class NetworkHsmService:
    def __init__(self, secret: Optional[str] = None):
        self._key = secret or secrets.token_hex(16)

    def reset(self) -> None:
        self._key = secrets.token_hex(16)

    def sign_payload(self, payload: str) -> Dict[str, str]:
        digest = hmac.new(self._key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return {"signature": digest, "algorithm": "HMAC-SHA256"}


class HarnessRegistry:
    """Aggregates all emulator services and exposes reset + helpers."""

    def __init__(self, config: Optional[Dict[str, any]] = None):
        config = config or {}
        totp_cfg = config.get("totp", {})
        smart_cfg = config.get("smartcard", {})
        hsm_cfg = config.get("network_hsm", {})

        self.otp = OTPService(drift_window=int(totp_cfg.get("drift_window", 30)))
        self.pkcs11 = PKCS11Service()
        self.fido = FidoService()
        self.smartcard = SmartCardService(default_pin=smart_cfg.get("card_pin", "0000"))
        self.mobile = MobileAuthenticatorService()
        self.network_hsm = NetworkHsmService(secret=hsm_cfg.get("api_key"))

    def reset_all(self) -> None:
        self.otp.reset()
        self.pkcs11.reset()
        self.fido.reset()
        self.smartcard.reset()
        self.mobile.reset()
        self.network_hsm.reset()
