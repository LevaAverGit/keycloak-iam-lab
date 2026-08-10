"""
Offline unit tests for the demo application — run WITHOUT Keycloak or Docker.

They exercise the security-critical local logic that must be correct regardless of
the running stack:

  * PKCE (S256) generation and the authorization-URL builder      (auth.py)
  * RBAC role extraction and enforcement                          (auth.py, main.py)
  * the public encryption JWK Set and the JWE encrypt/decrypt path (auth.py)
  * JWT validation — RS256 signature via JWKS, `iss` and `exp`     (auth.py)
  * the SAML request adapter                                       (saml.py)

JWT validation is tested against a locally generated RSA key whose public half is
injected in place of Keycloak's JWKS, so the real signature/issuer/expiry checks run
end to end with no network access. Live-stack behaviour (real token issuance, SAML
assertions, WebAuthn) is verified separately against the running lab.
"""

import asyncio
import base64
import hashlib
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo-app"))

import auth  # noqa: E402
import main  # noqa: E402
import saml  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from jose import jwe, jwk, jwt  # noqa: E402
from jose.exceptions import JWTError  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402


def _run(coro):
    """Run one coroutine to completion (validate_token is async, no plugin needed)."""
    return asyncio.run(coro)


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# --- TG-01: PKCE (S256) ---------------------------------------------------------
def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = auth.generate_pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected


def test_pkce_verifier_length_within_rfc7636_bounds():
    verifier, _ = auth.generate_pkce_pair()
    assert 43 <= len(verifier) <= 128


def test_pkce_verifier_uses_url_safe_alphabet():
    verifier, challenge = auth.generate_pkce_pair()
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    assert set(verifier) <= allowed
    assert set(challenge) <= allowed


def test_pkce_pairs_are_unique():
    first, _ = auth.generate_pkce_pair()
    second, _ = auth.generate_pkce_pair()
    assert first != second


# --- TG-02: Authorization URL ---------------------------------------------------
def test_authorize_url_carries_all_flow_parameters():
    url = auth.build_authorize_url("state-xyz", "challenge-abc")
    assert url.startswith(auth.AUTHORIZE_ENDPOINT)
    assert "/protocol/openid-connect/auth" in url
    assert "response_type=code" in url
    assert "code_challenge_method=S256" in url
    assert "state=state-xyz" in url
    assert f"client_id={auth.CLIENT_ID}" in url
    assert "code_challenge=challenge-abc" in url
    # scope and redirect_uri are URL-encoded in the query string
    assert "scope=" in url and "redirect_uri=" in url


# --- TG-03: Public encryption JWK Set ------------------------------------------
def test_public_encryption_jwks_shape():
    key = auth.public_encryption_jwks()["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "enc"
    assert key["alg"] == "RSA-OAEP"
    assert key["kid"] == auth.APP_ENC_KID
    assert key["n"] and key["e"]


def test_public_encryption_jwks_is_2048_bit():
    key = auth.public_encryption_jwks()["keys"][0]
    modulus = _b64url_decode(key["n"])
    # A 2048-bit modulus is 256 bytes (leading zero byte may or may not be present).
    assert 255 <= len(modulus) <= 256


def test_int_to_b64url_roundtrips():
    for value in (0, 1, 65537, 2 ** 512 + 12345):
        encoded = auth._int_to_b64url(value)
        decoded = int.from_bytes(_b64url_decode(encoded), "big")
        assert decoded == value


# --- TG-04: JWE roundtrip (Keycloak encrypts -> app decrypts) -------------------
def test_jwe_roundtrip_restores_inner_jws():
    inner_jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpc3MiOiJrYyJ9.signature"
    pub_key = auth.public_encryption_jwks()["keys"][0]
    encrypted = jwe.encrypt(
        inner_jws.encode(),
        pub_key,
        algorithm="RSA-OAEP",
        encryption="A128CBC-HS256",
    ).decode()
    assert encrypted != inner_jws
    assert encrypted.count(".") == 4  # compact JWE has five segments
    assert auth.decrypt_id_token(encrypted) == inner_jws


# --- RBAC: role extraction and enforcement -------------------------------------
def test_extract_roles_reads_realm_access():
    claims = {"realm_access": {"roles": ["app-user", "app-admin"]}}
    assert auth.extract_roles(claims) == ["app-user", "app-admin"]


def test_extract_roles_defaults_to_empty():
    assert auth.extract_roles({}) == []
    assert auth.extract_roles({"realm_access": {}}) == []


def test_require_role_rejects_anonymous_with_401():
    with pytest.raises(HTTPException) as exc:
        main.require_role(None, "app-user")
    assert exc.value.status_code == 401


def test_require_role_rejects_missing_role_with_403():
    claims = {"realm_access": {"roles": ["app-user"]}}
    with pytest.raises(HTTPException) as exc:
        main.require_role(claims, "app-admin")
    assert exc.value.status_code == 403


def test_require_role_allows_matching_role():
    claims = {"realm_access": {"roles": ["app-user", "app-admin"]}}
    assert main.require_role(claims, "app-admin") is claims


# --- Logout URL ----------------------------------------------------------------
def test_logout_url_without_id_token_hint():
    url = auth.logout_url()
    assert url.startswith(auth.LOGOUT_ENDPOINT)
    assert "post_logout_redirect_uri=" in url
    assert f"client_id={auth.CLIENT_ID}" in url
    assert "id_token_hint" not in url


def test_logout_url_includes_id_token_hint_when_provided():
    url = auth.logout_url("some-id-token")
    assert "id_token_hint=some-id-token" in url


# --- JWT validation against a locally injected JWKS ----------------------------
_SIGN_KID = "unit-test-signing-key"


@pytest.fixture(scope="module")
def signing_material():
    """A locally generated RS256 keypair plus the matching public JWK Set."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_jwk = jwk.construct(private_pem, algorithm="RS256").public_key().to_dict()
    public_jwk = {
        k: (v.decode() if isinstance(v, bytes) else v) for k, v in public_jwk.items()
    }
    public_jwk["kid"] = _SIGN_KID
    public_jwk["use"] = "sig"
    return private_pem, {"keys": [public_jwk]}


def _sign(private_pem: str, claims: dict, kid: str = _SIGN_KID) -> str:
    return jwt.encode(claims, private_pem, algorithm="RS256", headers={"kid": kid})


def _base_claims() -> dict:
    return {
        "sub": "user-123",
        "preferred_username": "user",
        "iss": auth.ISSUER,
        "exp": int(time.time()) + 300,
        "realm_access": {"roles": ["app-user", "app-admin"]},
    }


def _patch_jwks(monkeypatch, jwks: dict):
    async def _fake_jwks():
        return jwks

    monkeypatch.setattr(auth, "_get_jwks", _fake_jwks)


def test_validate_token_accepts_a_valid_token(monkeypatch, signing_material):
    private_pem, jwks = signing_material
    _patch_jwks(monkeypatch, jwks)
    token = _sign(private_pem, _base_claims())
    claims = _run(auth.validate_token(token))
    assert claims["sub"] == "user-123"
    assert claims["iss"] == auth.ISSUER
    assert auth.extract_roles(claims) == ["app-user", "app-admin"]


def test_validate_token_rejects_expired_token(monkeypatch, signing_material):
    private_pem, jwks = signing_material
    _patch_jwks(monkeypatch, jwks)
    claims = _base_claims()
    claims["exp"] = int(time.time()) - 30
    token = _sign(private_pem, claims)
    with pytest.raises(JWTError):
        _run(auth.validate_token(token))


def test_validate_token_rejects_wrong_issuer(monkeypatch, signing_material):
    private_pem, jwks = signing_material
    _patch_jwks(monkeypatch, jwks)
    claims = _base_claims()
    claims["iss"] = "http://attacker.example/realms/evil"
    token = _sign(private_pem, claims)
    with pytest.raises(JWTError):
        _run(auth.validate_token(token))


def test_validate_token_rejects_unknown_kid(monkeypatch, signing_material):
    private_pem, jwks = signing_material
    _patch_jwks(monkeypatch, jwks)
    token = _sign(private_pem, _base_claims(), kid="not-in-jwks")
    with pytest.raises(JWTError):
        _run(auth.validate_token(token))


# --- SAML request adapter (pure, no IdP metadata fetch) ------------------------
def test_saml_prepare_request_maps_fastapi_request():
    req = saml._prepare_request(
        "localhost:8000", "/saml/acs", {"q": "1"}, {"SAMLResponse": "x"}
    )
    # APP_HOST defaults to http:// in the lab, so https must be reported off.
    assert req["https"] == "off"
    assert req["http_host"] == "localhost:8000"
    assert req["script_name"] == "/saml/acs"
    assert req["get_data"] == {"q": "1"}
    assert req["post_data"] == {"SAMLResponse": "x"}
