"""Domain services that emulate token behavior in-memory."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional

from . import cbor


_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
AAGUID = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")


def _random_secret(length: int = 32) -> str:
    return "".join(secrets.choice(_BASE32_ALPHABET) for _ in range(length))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


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
    credential_id: bytes
    user_id: bytes
    user_handle: str
    rp_id: str
    origin: str
    private_key_pem: bytes
    public_key: bytes  # uncompressed (0x04 || X || Y)
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
        # legacy helper for tests: create random credential metadata
        cred = self._create_credential(
            rp_id=rp_id,
            origin=f"https://{rp_id}",
            challenge=secrets.token_bytes(16),
            user_id=user_id.encode(),
            user_handle=user_id,
        )
        return cred

    def authenticate(self, credential_b64: str, challenge: str) -> Dict[str, str | int]:
        cred = self._credentials.get(credential_b64)
        if not cred:
            raise KeyError("unknown credential")
        cred.sign_count += 1
        signature_material = f"{challenge}:{_b64url_encode(cred.public_key)}:{cred.sign_count}".encode("utf-8")
        signature = _b64url_encode(hashlib.sha256(signature_material).digest())
        return {
            "credential_id": credential_b64,
            "signature": signature,
            "sign_count": cred.sign_count,
        }

    # --- WebAuthn helpers ---

    def make_attestation(self, options: Dict[str, Any]) -> Dict[str, Any]:
        credential = self._create_credential(
            rp_id=options["rp"]["id"],
            origin=options["origin"],
            challenge=_b64url_decode(options["challenge"]),
            user_id=_b64url_decode(options["user"]["id"]),
            user_handle=options["user"]["name"],
        )
        credential_id_b64 = _b64url_encode(credential.credential_id)
        client_data = _build_client_data("webauthn.create", options["challenge"], options["origin"])
        client_hash = hashlib.sha256(client_data).digest()
        auth_data = _build_attested_auth_data(credential, sign_count=credential.sign_count)
        signature = _sign_with_private(credential.private_key_pem, auth_data + client_hash)
        att_obj = cbor.encode(
            {
                "fmt": "packed",
                "authData": auth_data,
                "attStmt": {"alg": -7, "sig": signature},
            }
        )
        return {
            "id": credential_id_b64,
            "rawId": credential_id_b64,
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url_encode(client_data),
                "attestationObject": _b64url_encode(att_obj),
            },
        }

    def make_assertion(self, options: Dict[str, Any]) -> Dict[str, Any]:
        allow_list = options.get("allowCredentials") or []
        if not allow_list:
            raise KeyError("allowCredentials required")
        credential_id = allow_list[0]["id"]
        cred = self._credentials.get(credential_id)
        if not cred:
            raise KeyError("unknown credential")
        cred.sign_count += 1
        client_data = _build_client_data("webauthn.get", options["challenge"], options["origin"])
        client_hash = hashlib.sha256(client_data).digest()
        auth_data = _build_assertion_auth_data(cred, cred.sign_count)
        signature = _sign_with_private(cred.private_key_pem, auth_data + client_hash)
        return {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": _b64url_encode(client_data),
                "authenticatorData": _b64url_encode(auth_data),
                "signature": _b64url_encode(signature),
                "userHandle": _b64url_encode(cred.user_id),
            },
        }

    def _create_credential(
        self,
        rp_id: str,
        origin: str,
        challenge: bytes,
        user_id: bytes,
        user_handle: str,
    ) -> FidoCredential:
        priv_pem = _generate_p256_private()
        pub_bytes = _extract_public_key(priv_pem)
        credential_id = secrets.token_bytes(16)
        cred = FidoCredential(
            credential_id=credential_id,
            user_id=user_id,
            user_handle=user_handle,
            rp_id=rp_id,
            origin=origin,
            private_key_pem=priv_pem,
            public_key=pub_bytes,
            sign_count=0,
        )
        self._credentials[_b64url_encode(credential_id)] = cred
        return cred


def _generate_p256_private() -> bytes:
    result = subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "prime256v1"],
        capture_output=True,
        check=True,
    )
    return result.stdout


def _extract_public_key(priv_pem: bytes) -> bytes:
    result = subprocess.run(
        ["openssl", "ec", "-text", "-noout"],
        input=priv_pem,
        capture_output=True,
        check=True,
    )
    lines = [line.strip() for line in result.stdout.decode().splitlines()]
    hex_bytes: List[str] = []
    collecting = False
    for line in lines:
        if not line or line.startswith("read") or line.startswith("writing"):
            continue
        if line.startswith("pub:"):
            collecting = True
            continue
        if collecting:
            if line.startswith("ASN1"):
                break
            hex_bytes.extend(part for part in line.split(":") if part)
    pub_bytes = bytes(int(h, 16) for h in hex_bytes)
    if not pub_bytes or pub_bytes[0] != 0x04:
        raise ValueError("unexpected public key format")
    return pub_bytes


def _sign_with_private(priv_pem: bytes, data: bytes) -> bytes:
    with NamedTemporaryFile(delete=False) as handle:
        handle.write(priv_pem)
        priv_path = handle.name
    try:
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", priv_path],
            input=data,
            capture_output=True,
            check=True,
        )
        return result.stdout
    finally:
        os.unlink(priv_path)


def _build_client_data(client_type: str, challenge_b64: str, origin: str) -> bytes:
    payload = {
        "type": client_type,
        "challenge": challenge_b64,
        "origin": origin,
        "crossOrigin": False,
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _build_attested_auth_data(credential: FidoCredential, sign_count: int) -> bytes:
    rp_hash = hashlib.sha256(credential.rp_id.encode("utf-8")).digest()
    flags = bytes([0x41])  # user present + attested credential data
    counter = sign_count.to_bytes(4, "big")
    credential_id = credential.credential_id
    cose_key = _cose_public_key(credential.public_key)
    attested = (
        AAGUID
        + len(credential_id).to_bytes(2, "big")
        + credential_id
        + cose_key
    )
    return rp_hash + flags + counter + attested


def _build_assertion_auth_data(credential: FidoCredential, sign_count: int) -> bytes:
    rp_hash = hashlib.sha256(credential.rp_id.encode("utf-8")).digest()
    flags = bytes([0x01])  # user present
    counter = sign_count.to_bytes(4, "big")
    return rp_hash + flags + counter


def _cose_public_key(public_key: bytes) -> bytes:
    if len(public_key) != 65 or public_key[0] != 0x04:
        raise ValueError("public key must be uncompressed P-256")
    x = public_key[1:33]
    y = public_key[33:65]
    cose_map = {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    return cbor.encode(cose_map)


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

    def refresh_certificate(self) -> SmartCardState:
        random_cert = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii")
        if self._state.inserted:
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


class PGPService:
    def __init__(self, default_name: str = "Harness User", default_email: str = "harness@example.com"):
        self.default_name = default_name
        self.default_email = default_email
        self._keys: Dict[str, Dict[str, Any]] = {}

    def reset(self) -> None:
        self._keys.clear()

    def generate_key(self, name: Optional[str] = None, email: Optional[str] = None) -> Dict[str, Any]:
        uid_name = name or self.default_name
        uid_email = email or self.default_email
        fingerprint = secrets.token_hex(20).upper()
        secret = secrets.token_bytes(32)
        self._keys[fingerprint] = {
            "fingerprint": fingerprint,
            "uids": [f"{uid_name} <{uid_email}>"],
            "secret": secret,
        }
        return {"fingerprint": fingerprint, "uids": [f"{uid_name} <{uid_email}>"]}

    def list_keys(self) -> List[Dict[str, Any]]:
        return [
            {"fingerprint": key["fingerprint"], "uids": key["uids"]}
            for key in self._keys.values()
        ]

    def sign(self, fingerprint: str, message: str) -> str:
        key = self._get_key(fingerprint)
        digest = hmac.new(key["secret"], message.encode("utf-8"), hashlib.sha256).digest()
        payload = base64.b64encode(digest).decode("ascii")
        return f"-----BEGIN PGP SIGNATURE-----\n{payload}\n-----END PGP SIGNATURE-----"

    def encrypt(self, fingerprint: str, message: str) -> str:
        key = self._get_key(fingerprint)
        data = message.encode("utf-8")
        keystream = self._keystream(key["secret"], len(data))
        cipher = bytes(a ^ b for a, b in zip(data, keystream))
        payload = base64.b64encode(cipher).decode("ascii")
        return f"-----BEGIN PGP MESSAGE-----\n{payload}\n-----END PGP MESSAGE-----"

    def decrypt(self, fingerprint: str, ciphertext: str) -> str:
        key = self._get_key(fingerprint)
        payload = self._extract_payload(ciphertext)
        try:
            data = base64.b64decode(payload)
        except binascii.Error as exc:
            raise ValueError("invalid PGP ciphertext payload") from exc
        keystream = self._keystream(key["secret"], len(data))
        plaintext = bytes(a ^ b for a, b in zip(data, keystream))
        return plaintext.decode("utf-8")

    def _get_key(self, fingerprint: str) -> Dict[str, Any]:
        key = self._keys.get(fingerprint)
        if not key:
            raise KeyError("unknown fingerprint")
        return key

    @staticmethod
    def _keystream(secret: bytes, length: int) -> bytes:
        output = bytearray()
        counter = 0
        while len(output) < length:
            counter_bytes = counter.to_bytes(4, "big")
            output.extend(hashlib.sha256(secret + counter_bytes).digest())
            counter += 1
        return bytes(output[:length])

    @staticmethod
    def _extract_payload(block: str) -> str:
        lines = [line for line in block.splitlines() if not line.startswith("-")]
        return "".join(lines)


class HarnessRegistry:
    """Aggregates all emulator services and exposes reset + helpers."""

    def __init__(self, config: Optional[Dict[str, any]] = None):
        config = config or {}
        totp_cfg = config.get("totp", {})
        smart_cfg = config.get("smartcard", {})
        hsm_cfg = config.get("network_hsm", {})
        pgp_cfg = config.get("pgp", {})

        self.otp = OTPService(drift_window=int(totp_cfg.get("drift_window", 30)))
        self.pkcs11 = PKCS11Service()
        self.fido = FidoService()
        self.smartcard = SmartCardService(default_pin=smart_cfg.get("card_pin", "0000"))
        self.mobile = MobileAuthenticatorService()
        self.network_hsm = NetworkHsmService(secret=hsm_cfg.get("api_key"))
        self.pgp = PGPService(
            default_name=pgp_cfg.get("default_name", "Harness User"),
            default_email=pgp_cfg.get("default_email", "harness@example.com"),
        )

    def reset_all(self) -> None:
        self.otp.reset()
        self.pkcs11.reset()
        self.fido.reset()
        self.smartcard.reset()
        self.mobile.reset()
        self.network_hsm.reset()
        self.pgp.reset()
