"""
Keycloak IAM Lab — demo application.

Demonstrates four OAuth2 / OIDC patterns against a Keycloak realm:
  - Authorization Code + PKCE  (browser login)         → /login, /callback, /dashboard
  - Role-based access control   (realm roles)           → /dashboard (app-user), /admin (app-admin)
  - Client Credentials          (machine-to-machine)    → /api/service-token
  - JWT validation              (JWKS, iss, exp)        → all protected routes

Tokens are kept in a signed server-side session cookie (lab scope).
"""

import os
import secrets

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from jose.exceptions import JWTError

import auth
import saml

app = FastAPI(title="Keycloak IAM Lab")
app.add_middleware(SessionMiddleware, secret_key=os.getenv("APP_SECRET_KEY", "dev-secret"))
templates = Jinja2Templates(directory="templates")


# --- Dependency-style helpers ---
async def current_claims(request: Request) -> dict | None:
    """Return validated token claims from the session, or None if not authenticated."""
    token = request.session.get("access_token")
    if not token:
        return None
    try:
        return await auth.validate_token(token)
    except JWTError:
        # Try a refresh before giving up.
        refresh = request.session.get("refresh_token")
        if refresh:
            try:
                tokens = await auth.refresh_access_token(refresh)
                request.session["access_token"] = tokens["access_token"]
                request.session["refresh_token"] = tokens.get("refresh_token", refresh)
                return await auth.validate_token(tokens["access_token"])
            except (JWTError, httpx.HTTPError):
                return None
        return None


def require_role(claims: dict | None, role: str) -> dict:
    """Raise 401/403 unless the claims carry the required realm role."""
    if claims is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if role not in auth.extract_roles(claims):
        raise HTTPException(status_code=403, detail=f"Role '{role}' required")
    return claims


# --- Public routes ---
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    claims = await current_claims(request)
    username = claims.get("preferred_username") if claims else None
    return templates.TemplateResponse("index.html", {"request": request, "username": username})


@app.get("/login")
async def login(request: Request):
    """Start the Authorization Code + PKCE flow."""
    verifier, challenge = auth.generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    request.session["pkce_verifier"] = verifier
    request.session["oauth_state"] = state
    return RedirectResponse(auth.build_authorize_url(state, challenge))


@app.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None):
    """Handle the OAuth2 redirect: validate state, exchange code, store tokens."""
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")
    if state != request.session.get("oauth_state"):
        raise HTTPException(status_code=400, detail="State mismatch (possible CSRF)")

    verifier = request.session.get("pkce_verifier")
    if not verifier:
        raise HTTPException(status_code=400, detail="Missing PKCE verifier")

    tokens = await auth.exchange_code_for_token(code, verifier)
    # Store only access + refresh tokens. The id_token is intentionally NOT kept:
    # three JWTs can exceed the browser's 4 KB cookie limit, and logout works via
    # client_id alone. (QA finding H1.)
    request.session["access_token"] = tokens["access_token"]
    request.session["refresh_token"] = tokens.get("refresh_token")

    # JWE demo: Keycloak delivers the ID token encrypted to this app's public key.
    # Decrypt it (JWE) → inner signed JWT (JWS) → validate signature/iss/exp.
    encrypted_id = tokens.get("id_token")
    if encrypted_id:
        try:
            inner_jws = auth.decrypt_id_token(encrypted_id)
            await auth.validate_token(inner_jws)
            request.session["id_token_jwe_ok"] = True
        except Exception:
            request.session["id_token_jwe_ok"] = False

    # One-time values no longer needed.
    request.session.pop("pkce_verifier", None)
    request.session.pop("oauth_state", None)
    return RedirectResponse("/dashboard")


# --- Protected routes (RBAC) ---
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    claims = require_role(await current_claims(request), "app-user")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "username": claims.get("preferred_username"),
            "email": claims.get("email"),
            "roles": auth.extract_roles(claims),
            "is_admin": "app-admin" in auth.extract_roles(claims),
            "jwe_ok": request.session.get("id_token_jwe_ok"),
        },
    )


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    claims = require_role(await current_claims(request), "app-admin")
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "username": claims.get("preferred_username"),
            "roles": auth.extract_roles(claims),
        },
    )


# --- API routes ---
@app.get("/api/whoami")
async def whoami(request: Request):
    """Return the validated JWT claims as JSON."""
    claims = await current_claims(request)
    if claims is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse(
        {
            "sub": claims.get("sub"),
            "preferred_username": claims.get("preferred_username"),
            "email": claims.get("email"),
            "roles": auth.extract_roles(claims),
            "issuer": claims.get("iss"),
            "expires_at": claims.get("exp"),
        }
    )


@app.get("/api/service-token")
async def service_token():
    """Demonstrate the Client Credentials flow (machine-to-machine)."""
    tokens = await auth.get_service_token()
    return JSONResponse(
        {
            "flow": "client_credentials",
            "token_type": tokens.get("token_type"),
            "expires_in": tokens.get("expires_in"),
            "access_token": tokens.get("access_token"),
        }
    )


@app.get("/logout")
async def logout(request: Request):
    """Clear the local session and end the Keycloak SSO session."""
    request.session.clear()
    return RedirectResponse(auth.logout_url())


# --- JWE: public key for Keycloak to encrypt ID tokens against ---
@app.get("/oidc/jwks")
async def oidc_jwks():
    """Public encryption JWK Set. Keycloak fetches this (jwks.url) to encrypt ID tokens."""
    return JSONResponse(auth.public_encryption_jwks())


# --- SAML 2.0 Service Provider routes ---
def _saml_host(request: Request) -> str:
    return request.headers.get("host", "localhost:8000")


@app.get("/saml/login")
async def saml_login(request: Request):
    """SP-initiated SSO: build the SAML AuthnRequest and redirect to Keycloak."""
    url = saml.build_login_redirect(_saml_host(request), dict(request.query_params))
    return RedirectResponse(url)


@app.post("/saml/acs")
async def saml_acs(request: Request):
    """Assertion Consumer Service: validate the SAML response from Keycloak."""
    form = await request.form()
    post_data = {key: form[key] for key in form}
    try:
        result = saml.process_acs(_saml_host(request), dict(request.query_params), post_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    request.session["saml_user"] = result["nameid"]
    request.session["saml_attributes"] = result["attributes"]
    return RedirectResponse("/saml/profile", status_code=303)


@app.get("/saml/profile", response_class=HTMLResponse)
async def saml_profile(request: Request):
    user = request.session.get("saml_user")
    if not user:
        raise HTTPException(status_code=401, detail="No SAML session")
    return templates.TemplateResponse(
        "saml_profile.html",
        {
            "request": request,
            "nameid": user,
            "attributes": request.session.get("saml_attributes", {}),
        },
    )


@app.get("/saml/metadata")
async def saml_metadata():
    """SP metadata XML."""
    try:
        return Response(content=saml.get_sp_metadata(), media_type="application/xml")
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/saml/sls")
async def saml_sls(request: Request):
    """Single Logout Service: clear the local SAML session."""
    request.session.pop("saml_user", None)
    request.session.pop("saml_attributes", None)
    return RedirectResponse("/")


@app.get("/health")
async def health():
    return {"status": "ok"}
