# Архитектура и OAuth2 flows

Технический разбор того, как устроен Keycloak IAM Lab и как реализован каждый flow.

---

## Компоненты и сетевое взаимодействие

```
                         Docker network: iam-lab
┌─────────────────────────────────────────────────────────────────────┐
│                                                                       │
│   ┌──────────────┐        ┌──────────────┐        ┌──────────────┐    │
│   │  demo-app    │        │   keycloak   │        │  postgres    │    │
│   │  :8000       │───────▶│   :8080      │───────▶│  :5432       │    │
│   └──────────────┘        └──────────────┘        └──────────────┘    │
│        ▲                        ▲                                      │
└────────┼────────────────────────┼─────────────────────────────────────┘
         │ localhost:8000          │ localhost:8080
         │                         │
    ┌────┴─────────────────────────┴────┐
    │            Браузер пользователя     │
    └─────────────────────────────────────┘
```

### Двойной URL Keycloak — ключевая деталь

Браузер и backend обращаются к Keycloak по разным адресам:

| Кто | URL | Зачем |
|-----|-----|-------|
| Браузер | `http://localhost:8080` (публичный) | redirect на форму логина, logout |
| demo-app | `http://keycloak:8080` (внутренний, DNS Docker) | server-to-server: обмен кода на токен, загрузка JWKS |

Это повторяет реальный деплой, где IdP имеет публичный хостнейм для пользователей и
внутренний адрес для backend-сервисов.

**Подводный камень (решён в проекте):** в dev-режиме Keycloak формирует claim `iss`
по хосту запроса. Так как backend ходит на `keycloak:8080`, `iss` мог бы стать
`http://keycloak:8080/...`, и проверка `iss` в demo-app (ожидающая `localhost:8080`)
провалилась бы. Поэтому в `docker-compose.yml` зафиксирован публичный frontend-URL:

```yaml
KC_HOSTNAME_URL: http://localhost:8080
KC_HOSTNAME_STRICT_BACKCHANNEL: "true"
```

Теперь `iss` всегда `http://localhost:8080/realms/iam-lab` независимо от канала.

---

## Flow 1 — Authorization Code + PKCE

Публичный клиент `demo-app` (без секрета), поэтому используется PKCE — защита от
перехвата авторизационного кода.

```
Браузер              demo-app                         Keycloak
   │                    │                                │
   │  GET /login        │                                │
   │ ──────────────────▶│                                │
   │                    │ генерит code_verifier +        │
   │                    │ code_challenge (S256) + state  │
   │                    │ кладёт verifier/state в сессию │
   │  302 →authorize?challenge&state                     │
   │ ◀──────────────────│                                │
   │  GET authorize     │                                │
   │ ───────────────────┼───────────────────────────────▶│
   │  логин + (MFA)     │                                │ проверяет креды
   │  302 →/callback?code&state                          │
   │ ◀──────────────────┼────────────────────────────────│
   │  GET /callback?code&state                           │
   │ ──────────────────▶│                                │
   │                    │ сверяет state (anti-CSRF)      │
   │                    │ POST token (code+verifier)     │
   │                    │ ──────────────────────────────▶│ проверяет challenge
   │                    │ ◀───────── access+refresh ─────│
   │                    │ кладёт токены в session-cookie │
   │  302 →/dashboard   │                                │
   │ ◀──────────────────│                                │
```

**Где в коде:**
- `auth.generate_pkce_pair()` — verifier + challenge (S256)
- `auth.build_authorize_url()` — сборка authorize-URL
- `main.login()` — старт flow, сохранение verifier и state
- `main.callback()` — проверка state, обмен кода
- `auth.exchange_code_for_token()` — POST на token endpoint

---

## Flow 2 — RBAC по realm-ролям

Роли (`app-user`, `app-admin`) кладутся в access token через protocol mapper в claim
`realm_access.roles`. Backend извлекает их и сверяет с требованием эндпоинта.

```python
def require_role(claims, role):
    if claims is None:
        raise HTTPException(401)          # не аутентифицирован
    if role not in extract_roles(claims):
        raise HTTPException(403)          # роли не хватает
    return claims
```

- `/dashboard` → требует `app-user`
- `/admin` → требует `app-admin`

---

## Flow 3 — MFA (TOTP)

Пользователь `admin-user` создан с required action `CONFIGURE_TOTP`. При первом входе
Keycloak обязывает привязать TOTP-приложение (Google Authenticator, FreeOTP). Далее
вход в админ-функции требует второй фактор. Политика TOTP задана на уровне realm
(`otpPolicyType: totp`, SHA1, 6 цифр, период 30с).

---

## Flow 4 — Client Credentials (machine-to-machine)

Конфиденциальный клиент `service-client` (с секретом, service accounts enabled)
получает токен без участия пользователя.

```
demo-app                                   Keycloak
   │  POST token                              │
   │  grant_type=client_credentials           │
   │  client_id + client_secret               │
   │ ────────────────────────────────────────▶│
   │ ◀──────────── access_token ──────────────│
```

**Где в коде:** `auth.get_service_token()` → эндпоинт `main.service_token()`.

---

## Валидация JWT

Каждый защищённый запрос валидирует access token:

1. Загрузка JWKS Keycloak (кэш в памяти, TTL 1 час) — `auth._get_jwks()`
2. Поиск ключа по `kid` из заголовка токена
3. `jwt.decode()` с проверкой:
   - **подписи** — RS256, ключ из JWKS (алгоритм захардкожен, защита от alg-confusion)
   - **issuer** — строго `http://localhost:8080/realms/iam-lab`
   - **expiry** — `exp`
4. При истёкшем токене `current_claims()` пытается обновить его по refresh token

**Где в коде:** `auth.validate_token()`, `main.current_claims()`.

---

## Flow 5 — SAML 2.0 SSO

Тот же demo-app выступает SP и по SAML, демонстрируя федерацию по обоим протоколам.
Keycloak — SAML IdP, клиент `saml-app`.

```
Браузер            demo-app (SP)                     Keycloak (IdP)
   │  GET /saml/login    │                                │
   │ ───────────────────▶│ строит SAML AuthnRequest       │
   │  302 →IdP SSO + SAMLRequest                          │
   │ ◀───────────────────│                                │
   │  логин              │                                │
   │ ────────────────────┼───────────────────────────────▶│ аутентифицирует
   │  POST /saml/acs (SAMLResponse, подписан)             │
   │ ◀───────────────────┼────────────────────────────────│
   │ ───────────────────▶│ проверяет подпись assertion,   │
   │                     │ audience=saml-app, извлекает    │
   │                     │ NameID + атрибуты               │
   │  302 →/saml/profile │                                │
```

**Ключевые решения:**
- SP-метаданные IdP (сертификат подписи) Keycloak генерирует при старте — SP тянет их
  динамически с `/realms/iam-lab/protocol/saml/descriptor` (`OneLogin_Saml2_IdPMetadataParser`).
- Подпись SP-запросов отключена (`authnRequestsSigned: false`), но assertion от IdP
  обязателен и проверяется (`wantAssertionsSigned: true`) — так не нужен SP-keypair.

**Где в коде:** `saml.py` (SP-логика), роуты `main.saml_*`. Требует нативный `xmlsec1`
(ставится в Dockerfile).

---

## Flow 6 — JWE: шифрование ID token

Если Flow 1-5 используют JWS (подпись), здесь добавляется JWE (шифрование). ID token
доставляется зашифрованным, чтобы его содержимое не читалось в транзите/логах.

```
demo-app                                   Keycloak
   │  Keycloak тянет публичный ключ:          │
   │  GET /oidc/jwks  ◀───────────────────────│
   │                                          │ шифрует ID token
   │                                          │ (RSA-OAEP + A128CBC-HS256)
   │  token response: id_token = JWE ◀────────│
   │  decrypt приватным ключом → JWS          │
   │  validate(JWS): подпись, iss, exp        │
```

**Архитектура ключей:** приложение генерирует RSA-пару в памяти при старте, отдаёт
публичную часть на `/oidc/jwks`, расшифровывает приватной. Приватный ключ не хранится
в репозитории. Access token остаётся обычным JWS — шифруется только ID token.

**Где в коде:** `auth.public_encryption_jwks()`, `auth.decrypt_id_token()`,
обработка в `main.callback()`, статус на `/dashboard`.

---

## Flow 7 — WebAuthn / FIDO2 (passkey)

Беспарольный/второй фактор на уровне Keycloak — код приложения не меняется. Realm
содержит `webAuthnPolicy*`, пользователь `passkey-user` имеет required action
`webauthn-register`. При первом входе Keycloak проводит регистрацию аутентификатора
(Touch ID, аппаратный ключ, виртуальный в DevTools), далее использует его как фактор.

Вся работа с FIDO2-протоколом (challenge, attestation, assertion) — на стороне
Keycloak; SP получает уже аутентифицированного пользователя обычным OIDC-flow.

---

## Структура realm `iam-lab`

| Объект | Значение |
|--------|----------|
| OIDC clients | `demo-app` (public, Auth Code + PKCE, ID token JWE), `service-client` (confidential, Client Credentials) |
| SAML client | `saml-app` (protocol saml, подписанные assertion) |
| Roles | `app-user`, `app-admin` |
| Users | `user` (app-user), `admin-user` (+app-admin, TOTP), `passkey-user` (WebAuthn) |
| Policies | OTP (TOTP, SHA1, 6 цифр), WebAuthn (rpId localhost, ES256/RS256) |
| Token lifespan | access 5 мин, SSO session idle 30 мин |
| Mappers | realm roles → `realm_access.roles` в access token |

Полная конфигурация — в [keycloak/realm-export.json](../keycloak/realm-export.json),
импортируется автоматически при старте контейнера.
