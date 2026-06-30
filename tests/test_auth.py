"""
Unit / component tests for the crypto & OIDC-helper layer (demo-app/auth.py).

These run WITHOUT Keycloak or Docker — they validate the security-critical local logic:
PKCE generation, authorization-URL construction, the public encryption JWK Set, and the
full JWE encrypt/decrypt roundtrip. Keycloak integration (token issuance, signature
validation, SAML, WebAuthn) is covered separately and requires the running stack.

Run:
    python -m venv .venv && source .venv/bin/activate
    pip install "python-jose[cryptography]==3.3.0" "cryptography==41.0.7" "httpx==0.27.0"
    python tests/test_auth.py
"""

import base64
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "demo-app"))
import auth
from jose import jwe

passed, failed = 0, 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


print("TG-01 PKCE (S256)")
verifier, challenge = auth.generate_pkce_pair()
expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
check("TC-01.1 challenge = base64url(sha256(verifier))", challenge == expected)
check("TC-01.2 verifier length 43..128 (RFC 7636)", 43 <= len(verifier) <= 128)
check("TC-01.3 two calls give different verifiers", auth.generate_pkce_pair()[0] != verifier)

print("TG-02 Authorize URL")
url = auth.build_authorize_url("state123", challenge)
check("TC-02.1 contains response_type=code", "response_type=code" in url)
check("TC-02.2 contains code_challenge_method=S256", "code_challenge_method=S256" in url)
check("TC-02.3 contains the state", "state123" in url)
check("TC-02.4 points at realm auth endpoint", "/protocol/openid-connect/auth" in url)

print("TG-03 Public encryption JWKS")
jwks = auth.public_encryption_jwks()
key = jwks["keys"][0]
check("TC-03.1 kty=RSA", key["kty"] == "RSA")
check("TC-03.2 use=enc", key["use"] == "enc")
check("TC-03.3 alg=RSA-OAEP", key["alg"] == "RSA-OAEP")
check("TC-03.4 has modulus n and exponent e", bool(key.get("n")) and bool(key.get("e")))

print("TG-04 JWE roundtrip (encrypt as Keycloak would -> app decrypts)")
sample_inner_jws = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMiLCJpc3MiOiJrYyJ9.signature"
encrypted = jwe.encrypt(
    sample_inner_jws.encode(),
    key,
    algorithm="RSA-OAEP",
    encryption="A128CBC-HS256",
).decode()
check("TC-04.1 ciphertext differs from plaintext", encrypted != sample_inner_jws)
check("TC-04.2 JWE has 5 segments (compact form)", encrypted.count(".") == 4)
decrypted = auth.decrypt_id_token(encrypted)
check("TC-04.3 decrypt(private) == original inner JWT", decrypted == sample_inner_jws)

print(f"\nTOTAL: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
