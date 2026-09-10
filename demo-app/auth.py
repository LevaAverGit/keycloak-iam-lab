"""
OAuth2 / OIDC / JWT helpers for the Keycloak IAM Lab demo application.

Splits Keycloak access into two URLs:
- KEYCLOAK_URL (public, http://localhost:8080)  — browser redirects, token issuer (iss)
- KEYCLOAK_INTERNAL_URL (http://keycloak:8080)  — server-to-server: token exchange, JWKS

This mirrors a real deployment where the IdP has a public hostname for users and an
internal address for backend services.
"""

import base64
import hashlib
import os
import secrets
import time

import httpx
from jose import jwt, jwe
from jose.exceptions import JWTError
from jose.utils import base64url_encode
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Configuration from environment (no secrets hardcoded) ---
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_INTERNAL_URL = os.getenv("KEYCLOAK_INTERNAL_URL", KEYCLOAK_URL)
REALM = os.getenv("KEYCLOAK_REALM", "iam-lab")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "demo-app")
SERVICE_CLIENT_ID = "service-client"
SERVICE_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET", "service-client-secret")
APP_HOST = os.getenv("APP_HOST", "http://localhost:8000")
REDIRECT_URI = f"{APP_HOST}/callback"

# Public issuer — what the token's `iss` claim will contain.
ISSUER = f"{KEYCLOAK_URL}/realms/{REALM}"

# OIDC endpoints (server-to-server use the internal URL).
TOKEN_ENDPOINT = f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/token"
JWKS_ENDPOINT = f"{KEYCLOAK_INTERNAL_URL}/realms/{REALM}/protocol/openid-connect/certs"
LOGOUT_ENDPOINT = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
AUTHORIZE_ENDPOINT = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth"

# Simple in-memory JWKS cache (lab scope).
_jwks_cache: dict | None = None
_jwks_fetched_at: float = 0.0
_JWKS_TTL = 3600


# --- PKCE (Proof Key for Code Exchange) ---
def generate_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for the S256 PKCE method."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(40)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def build_authorize_url(state: str, code_challenge: str) -> str:
    """Build the Keycloak authorization URL for the Authorization Code + PKCE flow."""
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTHORIZE_ENDPOINT}?{httpx.QueryParams(params)}"


# --- Token exchange ---
async def exchange_code_for_token(code: str, code_verifier: str) -> dict:
    """Authorization Code flow: exchange an authorization code for tokens."""
    data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(TOKEN_ENDPOINT, data=data)
        resp.raise_for_status()
        return resp.json()


async def get_service_token() -> dict:
    """Client Credentials flow: machine-to-machine token for the confidential client."""
    data = {
        "grant_type": "client_credentials",
        "client_id": SERVICE_CLIENT_ID,
        "client_secret": SERVICE_CLIENT_SECRET,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(TOKEN_ENDPOINT, data=data)
        resp.raise_for_status()
        return resp.json()


async def refresh_access_token(refresh_token: str) -> dict:
    """Exchange a refresh token for a fresh access token."""
    data = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_token,
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(TOKEN_ENDPOINT, data=data)
        resp.raise_for_status()
        return resp.json()


# --- JWKS + JWT validation ---
async def _get_jwks(force: bool = False) -> dict:
    """Fetch and cache the realm's JSON Web Key Set used to verify token signatures."""
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if force or _jwks_cache is None or (now - _jwks_fetched_at) > _JWKS_TTL:
        async with httpx.AsyncClient() as client:
            resp = await client.get(JWKS_ENDPOINT)
            resp.raise_for_status()
            _jwks_cache = resp.json()
            _jwks_fetched_at = now
    return _jwks_cache


def _find_key(jwks: dict, kid: str | None) -> dict | None:
    return next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)


async def validate_token(token: str) -> dict:
    """
    Validate a JWT access token: signature (JWKS), issuer, expiry, and that it was
    issued for this client. Returns the decoded claims, or raises JWTError on failure.
    """
    kid = jwt.get_unverified_header(token).get("kid")

    jwks = await _get_jwks()
    key = _find_key(jwks, kid)
    if key is None:
        # kid absent from the cached set usually means Keycloak rotated its signing
        # keys. Force one refresh before rejecting, so rotation doesn't fail every
        # request until the cache TTL expires.
        jwks = await _get_jwks(force=True)
        key = _find_key(jwks, kid)
    if key is None:
        raise JWTError("Signing key not found in JWKS")

    claims = jwt.decode(
        token,
        key,
        algorithms=["RS256"],  # fixed allow-list — do not trust alg from the token/JWKS
        issuer=ISSUER,
        options={"verify_aud": False},  # Keycloak puts client in azp, not aud, by default
    )

    # aud is not checked (Keycloak leaves it "account"), so pin the authorized party:
    # without this, any token minted by the realm for a *different* client would be
    # accepted here (confused-deputy / token reuse across clients).
    if claims.get("azp") != CLIENT_ID:
        raise JWTError(f"Token azp '{claims.get('azp')}' is not this client '{CLIENT_ID}'")

    return claims


def extract_roles(claims: dict) -> list[str]:
    """Pull realm roles out of the decoded token claims."""
    return claims.get("realm_access", {}).get("roles", [])


def logout_url(id_token: str | None = None) -> str:
    """Build the Keycloak end-session URL, returning the user to the app home page."""
    params = {"post_logout_redirect_uri": APP_HOST, "client_id": CLIENT_ID}
    if id_token:
        params["id_token_hint"] = id_token
    return f"{LOGOUT_ENDPOINT}?{httpx.QueryParams(params)}"


# --- JWE: encrypted ID tokens ---
# The app owns an RSA keypair. Keycloak fetches the public key from /oidc/jwks and
# encrypts the ID token to it (RSA-OAEP + A128CBC-HS256). The app decrypts with the
# private key. The keypair is generated in-memory at startup — a lab simplification;
# in production use a managed/rotated key from a vault, not an ephemeral one.
APP_ENC_KID = "demo-app-enc-key"
_enc_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_enc_private_pem = _enc_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()


def _int_to_b64url(value: int) -> str:
    byte_len = (value.bit_length() + 7) // 8
    return base64url_encode(value.to_bytes(byte_len, "big")).decode()


def public_encryption_jwks() -> dict:
    """Public JWK Set served to Keycloak so it can encrypt ID tokens to this app."""
    numbers = _enc_private_key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "enc",
                "alg": "RSA-OAEP",
                "kid": APP_ENC_KID,
                "n": _int_to_b64url(numbers.n),
                "e": _int_to_b64url(numbers.e),
            }
        ]
    }


def decrypt_id_token(encrypted: str) -> str:
    """Decrypt a JWE-wrapped ID token, returning the inner signed JWT (JWS) as a string."""
    return jwe.decrypt(encrypted, _enc_private_pem).decode()
