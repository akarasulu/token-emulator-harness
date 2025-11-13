import base64

from control_api.main import TestClient, app


client = TestClient(app)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def test_totp_seed_and_code():
    seed_resp = client.post("/otp/seed", json={"type": "totp"})
    assert seed_resp.status_code == 200
    seed = seed_resp.json()
    assert "seed_id" in seed and "secret" in seed

    code_resp = client.get(f"/otp/code/{seed['seed_id']}")
    assert code_resp.status_code == 200
    code_payload = code_resp.json()
    assert code_payload["seed_id"] == seed["seed_id"]
    assert len(code_payload["code"]) == 6


def test_pkcs11_key_lifecycle():
    create_resp = client.post("/pkcs11/keys", json={"label": "integration"})
    assert create_resp.status_code == 200
    created = create_resp.json()
    assert created["label"] == "integration"

    list_resp = client.get("/pkcs11/keys")
    keys = list_resp.json()
    assert any(k["key_id"] == created["key_id"] for k in keys)


def test_fido_registration_and_authentication():
    reg_resp = client.post("/fido2/register", json={"user_id": "user1", "rp_id": "example.com"})
    assert reg_resp.status_code == 200
    credential = reg_resp.json()
    assert "credential_id" in credential

    auth_resp = client.post(
        "/fido2/authenticate",
        json={"credential_id": credential["credential_id"], "challenge": "abc123"},
    )
    assert auth_resp.status_code == 200
    assertion = auth_resp.json()
    assert assertion["credential_id"] == credential["credential_id"]
    assert assertion["sign_count"] == 1


def test_smartcard_flow():
    insert_resp = client.post("/smartcard/insert")
    assert insert_resp.status_code == 200
    status_resp = client.get("/smartcard/status")
    status = status_resp.json()
    assert status["inserted"] is True
    assert status["certificate"]

    client.post("/smartcard/remove")
    status = client.get("/smartcard/status").json()
    assert status["inserted"] is False


def test_mobile_pair_and_assertion():
    pair_resp = client.post("/mobile/pair", json={"device_id": "mobile1"})
    assert pair_resp.status_code == 200
    assert pair_resp.json()["paired"] is True

    assertion_resp = client.post("/mobile/assert", json={"device_id": "mobile1", "challenge": "hello"})
    assert assertion_resp.status_code == 200
    assert assertion_resp.json()["device_id"] == "mobile1"


def test_network_hsm_signing():
    resp = client.post("/network_hsm/sign", json={"payload": "important"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["algorithm"] == "HMAC-SHA256"
    assert len(data["signature"]) == 64


def test_issue_ocra_challenge():
    resp = client.post("/issue_ocra_challenge")
    assert resp.status_code == 200
    assert resp.json()["challenge"]


def test_reset_clears_state():
    # create state
    client.post("/pkcs11/keys", json={"label": "to-reset"})
    resp = client.post("/reset_all")
    assert resp.status_code == 200
    keys = client.get("/pkcs11/keys").json()
    assert keys == []


def test_pgp_endpoints_flow():
    create_resp = client.post("/pgp/keys", json={"name": "Tester", "email": "tester@example.com"})
    assert create_resp.status_code == 200
    pgp_key = create_resp.json()
    fingerprint = pgp_key.get("fingerprint")
    assert fingerprint

    sign_resp = client.post("/pgp/sign", json={"fingerprint": fingerprint, "message": "hello"})
    assert "BEGIN PGP SIGNATURE" in sign_resp.json()["signature"]

    encrypt_resp = client.post("/pgp/encrypt", json={"fingerprint": fingerprint, "message": "secret"})
    ciphertext = encrypt_resp.json()["ciphertext"]
    assert "BEGIN PGP MESSAGE" in ciphertext

    decrypt_resp = client.post("/pgp/decrypt", json={"fingerprint": fingerprint, "ciphertext": ciphertext})
    assert decrypt_resp.json()["plaintext"].strip() == "secret"

    list_resp = client.get("/pgp/keys")
    assert any(key["fingerprint"] == fingerprint for key in list_resp.json())


def test_bridge_register_and_authenticate_roundtrip():
    challenge = _b64url(b"samplechallenge123")
    user_id = _b64url(b"user-1")
    creation = {
        "challenge": challenge,
        "origin": "https://example.com",
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": user_id, "name": "user-1", "displayName": "User One"},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
    }
    reg = client.post("/bridge/register", json=creation)
    assert reg.status_code == 200
    payload = reg.json()
    assert payload["type"] == "public-key"
    attestation = payload["response"]
    assert _decode(attestation["clientDataJSON"])
    assert _decode(attestation["attestationObject"])

    request = {
        "challenge": challenge,
        "origin": "https://example.com",
        "rpId": "example.com",
        "allowCredentials": [{"id": payload["id"], "type": "public-key"}],
    }
    assertion = client.post("/bridge/authenticate", json=request)
    assert assertion.status_code == 200
    assertion_payload = assertion.json()
    assert _decode(assertion_payload["response"]["clientDataJSON"])
    assert _decode(assertion_payload["response"]["authenticatorData"])
    assert _decode(assertion_payload["response"]["signature"])


def test_bridge_script_and_docs_served():
    js_resp = client.get("/bridge/webauthn.js")
    assert js_resp.status_code == 200
    assert "navigator.credentials" in js_resp.text()

    spec_resp = client.get("/openapi.yaml")
    assert spec_resp.status_code == 200
    assert "openapi: 3.0.3" in spec_resp.text()

    docs_resp = client.get("/docs")
    assert docs_resp.status_code == 200
    assert "<html" in docs_resp.text().lower()
