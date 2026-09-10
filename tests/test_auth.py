"""
Unit / component tests for the crypto & OIDC-helper layer (demo-app/auth.py).

Runs WITHOUT Keycloak or Docker — it exercises the security-critical local logic:
PKCE generation, authorize-URL construction, the public encryption JWK Set, the JWE
encrypt/decrypt roundtrip, and JWT validation (signature, alg-confusion resistance,
issuer, expiry, azp/client binding). The JWKS fetch is stubbed so signature validation
runs offline against a locally generated RSA key.

Run:
    python -m venv .venv && source .venv/bin/activate
    pip install "python-jose[cryptography]==3.3.0" "cryptography==41.0.7" "httpx==0.27.0" pytest
    pytest -q
"""

import asyncio
import base64
import hashlib
import os
import sys
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwe, jwt
from jose.exceptions import JWTError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo-app"))
import auth  # noqa: E402


def _rsa_signing_key(kid: str) -> tuple[str, dict]:
    """Generate an RSA keypair and return (private PEM, public JWK) for RS256 signing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": auth._int_to_b64url(pub.n),
        "e": auth._int_to_b64url(pub.e),
    }
    return pem, jwk


# One signing key shared across the validation tests (keygen is the slow part).
_SIGN_KID = "test-sig-key"
_SIGN_PEM, _SIGN_JWK = _rsa_signing_key(_SIGN_KID)


def _make_token(pem, *, alg="RS256", kid=_SIGN_KID, iss=None, azp=None, exp_delta=300):
    claims = {
        "sub": "user-123",
        "iss": auth.ISSUER if iss is None else iss,
        "azp": auth.CLIENT_ID if azp is None else azp,
        "exp": int(time.time()) + exp_delta,
        "realm_access": {"roles": ["app-user"]},
    }
    return jwt.encode(claims, pem, algorithm=alg, headers={"kid": kid})


@pytest.fixture
def stub_jwks(monkeypatch):
    """Point auth._get_jwks at a fixed local JWKS (no network)."""
    async def _fake(force=False):
        return {"keys": [_SIGN_JWK]}

    monkeypatch.setattr(auth, "_get_jwks", _fake)


# --- PKCE (RFC 7636, S256) ---
def test_pkce_challenge_is_sha256_of_verifier():
    verifier, challenge = auth.generate_pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected


def test_pkce_verifier_length_in_rfc_range():
    verifier, _ = auth.generate_pkce_pair()
    assert 43 <= len(verifier) <= 128


def test_pkce_verifier_is_unpadded_urlsafe():
    verifier, challenge = auth.generate_pkce_pair()
    for value in (verifier, challenge):
        assert "=" not in value and "+" not in value and "/" not in value


def test_pkce_pairs_are_unique():
    assert auth.generate_pkce_pair()[0] != auth.generate_pkce_pair()[0]


# --- Authorize URL ---
def test_authorize_url_carries_flow_params():
    url = auth.build_authorize_url("state123", "chal")
    assert "response_type=code" in url
    assert "code_challenge_method=S256" in url
    assert "state123" in url
    assert "/protocol/openid-connect/auth" in url


# --- Public encryption JWKS ---
def test_encryption_jwks_advertises_rsa_oaep_enc_key():
    key = auth.public_encryption_jwks()["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "enc"
    assert key["alg"] == "RSA-OAEP"
    assert key["kid"] == auth.APP_ENC_KID
    assert key["n"] and key["e"]


# --- JWE roundtrip: encrypt as Keycloak would, app decrypts ---
_SAMPLE_JWS = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpc3MiOiJrYyJ9.signature"


def _encrypt_to(jwk: dict, payload: bytes = _SAMPLE_JWS.encode()) -> str:
    return jwe.encrypt(
        payload, jwk, algorithm="RSA-OAEP", encryption="A128CBC-HS256"
    ).decode()


def test_jwe_roundtrip_recovers_plaintext():
    encrypted = _encrypt_to(auth.public_encryption_jwks()["keys"][0])
    assert encrypted != _SAMPLE_JWS
    assert encrypted.count(".") == 4  # compact JWE: 5 segments
    assert auth.decrypt_id_token(encrypted) == _SAMPLE_JWS


def test_jwe_decrypt_rejects_tampered_ciphertext():
    encrypted = _encrypt_to(auth.public_encryption_jwks()["keys"][0])
    header, ek, iv, ct, tag = encrypted.split(".")
    tampered = ".".join([header, ek, iv, ct, tag[:-2] + ("AA" if tag[-2:] != "AA" else "BB")])
    with pytest.raises(Exception):
        auth.decrypt_id_token(tampered)


def test_jwe_decrypt_rejects_wrong_recipient_key():
    _, foreign_sig_jwk = _rsa_signing_key("foreign")
    foreign_enc_jwk = {**foreign_sig_jwk, "use": "enc", "alg": "RSA-OAEP"}
    encrypted = _encrypt_to(foreign_enc_jwk)  # encrypted to a key the app doesn't hold
    with pytest.raises(Exception):
        auth.decrypt_id_token(encrypted)


# --- extract_roles ---
def test_extract_roles_reads_realm_access():
    assert auth.extract_roles({"realm_access": {"roles": ["app-admin"]}}) == ["app-admin"]


def test_extract_roles_defaults_empty():
    assert auth.extract_roles({}) == []
    assert auth.extract_roles({"realm_access": {}}) == []


# --- JWT validation (offline, stubbed JWKS) ---
def test_validate_accepts_well_formed_token(stub_jwks):
    token = _make_token(_SIGN_PEM)
    claims = asyncio.run(auth.validate_token(token))
    assert claims["sub"] == "user-123"


def test_validate_rejects_alg_confusion_hs256(stub_jwks):
    # Downgrade attempt: a token that asks to be verified with a symmetric alg (HS256).
    # The RS256-only allow-list must refuse it outright — never fall back to treating the
    # RSA public key material as an HMAC secret.
    forged = _make_token("attacker-chosen-secret", alg="HS256")
    with pytest.raises(JWTError):
        asyncio.run(auth.validate_token(forged))


def test_validate_rejects_wrong_issuer(stub_jwks):
    token = _make_token(_SIGN_PEM, iss="http://evil.example/realms/iam-lab")
    with pytest.raises(JWTError):
        asyncio.run(auth.validate_token(token))


def test_validate_rejects_expired_token(stub_jwks):
    token = _make_token(_SIGN_PEM, exp_delta=-10)
    with pytest.raises(JWTError):
        asyncio.run(auth.validate_token(token))


def test_validate_rejects_token_for_other_client(stub_jwks):
    # Token correctly signed by the realm but minted for a different client.
    token = _make_token(_SIGN_PEM, azp="some-other-client")
    with pytest.raises(JWTError):
        asyncio.run(auth.validate_token(token))


def test_validate_refreshes_jwks_on_kid_miss(monkeypatch):
    # Simulate signing-key rotation: the cached set lacks the token's kid, and only a
    # forced refresh returns it. Validation must recover instead of failing.
    calls = {"n": 0}

    async def _fake(force=False):
        calls["n"] += 1
        return {"keys": [_SIGN_JWK]} if force else {"keys": []}

    monkeypatch.setattr(auth, "_get_jwks", _fake)
    claims = asyncio.run(auth.validate_token(_make_token(_SIGN_PEM)))
    assert claims["sub"] == "user-123"
    assert calls["n"] == 2  # initial miss + one forced refresh


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
