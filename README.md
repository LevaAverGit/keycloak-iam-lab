# Keycloak IAM Lab

![Keycloak](https://img.shields.io/badge/Keycloak-IAM-4D4D4D)
![OAuth2 / OIDC](https://img.shields.io/badge/OAuth2-OIDC-EB5424)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

Лабораторный проект, демонстрирующий построение Identity & Access Management на базе
**Keycloak**: OAuth2, OpenID Connect, валидация JWT, ролевая модель (RBAC) и
многофакторная аутентификация (MFA/TOTP). Backend — **FastAPI**, вся инфраструктура
поднимается одной командой через **Docker Compose**.

---

## Архитектура

```
┌──────────┐   1. /login (Authorization Code + PKCE)   ┌──────────────┐
│          │ ────────────────────────────────────────▶ │              │
│ Браузер  │   2. логин + MFA (TOTP)                    │   Keycloak   │
│          │ ◀──────────────────────────────────────── │  (realm:     │
│          │   3. redirect /callback?code=...           │   iam-lab)   │
└────┬─────┘                                            └──────┬───────┘
     │                                                         │
     │ 4. cookie сессии (access+refresh)         server-to-    │
     ▼                                           server        ▼
┌──────────────┐  5. обмен code→token, JWKS  ┌──────────────────────┐
│   demo-app   │ ──────────────────────────▶ │ token / certs        │
│  (FastAPI)   │  6. валидация JWT (RS256,    │ endpoints            │
│              │     iss, exp) + проверка роли└──────────────────────┘
└──────────────┘
        │
        ▼
   PostgreSQL (хранилище Keycloak)
```

**Компоненты:**

| Компонент | Роль |
|-----------|------|
| Keycloak 24 | Identity Provider — выпуск и подпись токенов, MFA, хранение пользователей и ролей |
| demo-app (FastAPI) | Relying Party — инициирует flows, валидирует JWT, разграничивает доступ по ролям |
| PostgreSQL 15 | Персистентное хранилище Keycloak |

Подробное описание flows — в [docs/architecture.md](docs/architecture.md).

---

## Демонстрируемые OAuth2 / OIDC flows

| Flow | Эндпоинт | Что показывает |
|------|----------|----------------|
| Authorization Code + PKCE | `/login` → `/callback` | Безопасный браузерный вход публичного клиента |
| SAML 2.0 SSO | `/saml/login` → `/saml/acs` | Федерация по второму протоколу (тот же app как SAML SP) |
| JWE (шифрование токена) | `/callback`, `/oidc/jwks` | ID token приходит зашифрованным, app расшифровывает приватным ключом |
| WebAuthn / FIDO2 | вход под `passkey-user` | Passkey как фактор аутентификации |
| MFA (TOTP) | вход под `admin-user` | Обязательная многофакторная аутентификация |
| RBAC по realm-ролям | `/dashboard`, `/admin` | Разграничение доступа `app-user` / `app-admin` |
| Client Credentials | `/api/service-token` | Machine-to-machine токен конфиденциального клиента |
| JWT-валидация (JWS) | все защищённые роуты | Проверка подписи (JWKS), `iss`, `exp` |

---

## Быстрый старт

> Требуется установленный **Docker Desktop** (Docker + Docker Compose).

```bash
# 1. Скопировать шаблон переменных окружения
cp .env.example .env

# 2. Поднять стек (PostgreSQL + Keycloak + demo-app)
docker compose up -d

# 3. Подождать ~30-40 секунд: Keycloak импортирует realm iam-lab при первом старте.
#    Прогресс можно смотреть так:
docker compose logs -f keycloak
#    Готово, когда в логах появится строка про запуск на порту 8080.

# 4. Открыть приложение
open http://localhost:8000

# Консоль администратора Keycloak (admin / admin):
open http://localhost:8080
```

Остановить и удалить всё:

```bash
docker compose down -v
```

---

## Тестовые учётные записи

| Логин | Пароль | Роли | Особенность |
|-------|--------|------|-------------|
| `user` | `user` | `app-user` | Обычный пользователь, доступ к `/dashboard` |
| `admin-user` | `admin` | `app-user`, `app-admin` | При первом входе Keycloak потребует настроить TOTP (MFA) |
| `passkey-user` | `passkey` | `app-user` | При первом входе Keycloak потребует зарегистрировать passkey (WebAuthn) |

---

## Демо-сценарии

### Сценарий 1 — обычный вход (Authorization Code + PKCE)
1. Открыть http://localhost:8000 → **Войти через Keycloak**
2. Авторизоваться как `user` / `user`
3. Попадаем на `/dashboard` — видны имя, email и роль `app-user`
4. Открыть `/api/whoami` — JSON с валидированными claims из JWT

### Сценарий 2 — RBAC: доступ запрещён
1. Под пользователем `user` открыть http://localhost:8000/admin
2. Получаем **403 Forbidden** — нет роли `app-admin`

### Сценарий 3 — администратор + MFA
1. Выйти, войти как `admin-user` / `admin`
2. Keycloak предложит настроить TOTP — отсканировать QR в Google Authenticator / FreeOTP
3. Ввести одноразовый код → доступ к `/admin` открыт

### Сценарий 4 — machine-to-machine (Client Credentials)
1. Открыть http://localhost:8000/api/service-token
2. Получаем `access_token`, выпущенный без участия пользователя — для service-client

### Сценарий 5 — вход через SAML 2.0
1. На главной нажать **Войти через SAML**
2. Авторизоваться в Keycloak (например `user` / `user`)
3. Keycloak отправляет подписанный SAML-assertion на `/saml/acs`
4. Приложение проверяет подпись и показывает NameID и атрибуты из assertion
5. SP-метаданные доступны на http://localhost:8000/saml/metadata

### Сценарий 6 — passkey (WebAuthn / FIDO2)
1. Войти как `passkey-user` / `passkey`
2. Keycloak предложит зарегистрировать passkey — Touch ID, ключ безопасности или
   виртуальный аутентификатор (в Chrome DevTools → WebAuthn)
3. Последующие входы используют passkey как фактор

### Сценарий 7 — шифрование токена (JWE)
1. Войти обычным способом (`user` / `user`)
2. В личном кабинете — статус **ID token (JWE): зашифрован и расшифрован ✓**
3. Keycloak зашифровал ID token публичным ключом приложения (с `/oidc/jwks`),
   приложение расшифровало его приватным ключом

---

## Технологии

| Слой | Технология |
|------|-----------|
| Identity Provider | Keycloak 24 |
| Backend | Python 3.11, FastAPI, Uvicorn |
| JWT / JWE | python-jose (RS256 подпись, RSA-OAEP шифрование) |
| SAML | python3-saml (xmlsec) |
| HTTP-клиент | httpx |
| Шаблоны | Jinja2 |
| Инфраструктура | Docker Compose, PostgreSQL 15 |

---

## Релевантные концепции ИБ

- **OAuth2** — фреймворк делегированной авторизации
- **OpenID Connect** — слой аутентификации поверх OAuth2 (id_token, claims)
- **SAML 2.0** — федерация по XML-протоколу (IdP, SP, assertion)
- **PKCE** — защита Authorization Code flow от перехвата кода
- **JWT / JWS / JWE** — токены: подпись (JWS) и шифрование (JWE)
- **JWKS** — проверка подписи и публикация ключей шифрования
- **RBAC** — разграничение доступа по ролям
- **MFA / TOTP** — второй фактор аутентификации
- **WebAuthn / FIDO2** — беспарольная аутентификация через passkey
- **Confidential vs Public client** — модели доверия клиентских приложений

---

## Ограничения (lab scope)

Проект демонстрационный. В продакшене обязательно учесть:

- **Токены в session-cookie.** Cookie подписана, но не зашифрована — для прода токены
  держат на сервере (Redis/БД), cookie оставляют только идентификатор сессии.
- **`/api/service-token` открыт.** Эндпоинт намеренно отдаёт machine-токен без
  авторизации, чтобы показать flow. В реальной системе так делать нельзя — это утечка
  bearer-токена.
- **HTTP без TLS.** Локальный стенд работает по http. В проде — только https,
  cookie с флагами `Secure` и `HttpOnly`.
- **Дефолтные пароли и секреты.** `admin/admin`, тестовые пароли и секрет клиента —
  только для лабы. Менять в `.env` и Keycloak перед любым реальным использованием.
