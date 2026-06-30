# PRD — Keycloak IAM Lab

## Цель проекта

Портфолийный лаборатории проект, демонстрирующий практические знания IAM/IDM архитектуры:
OAuth2, OpenID Connect, JWT, MFA. Предназначен для демонстрации работодателям уровня
архитектора ИБ (целевая вакансия: Архитектор ИБ / IAM-специалист).

## Стек

- **IAM:** Keycloak 24 (Docker)
- **Backend:** Python 3.11 + FastAPI
- **Auth-библиотека:** python-jose (JWT), httpx (token exchange)
- **Инфра:** Docker Compose (Keycloak + PostgreSQL + demo-app)
- **Документация:** Markdown + draw.io схемы

## OAuth2 flows к реализации

| Flow | Описание | Где демонстрируется |
|------|----------|---------------------|
| Authorization Code + PKCE | Браузерный логин через Keycloak | /login → /callback → /dashboard |
| Client Credentials | Machine-to-machine токен | /api/service-token |
| Token Introspection | Проверка активности токена | middleware |
| Refresh Token | Обновление сессии | автоматически в middleware |

## Keycloak realm конфигурация

- **Realm:** `iam-lab`
- **Clients:**
  - `demo-app` — public client, Authorization Code + PKCE
  - `service-client` — confidential client, Client Credentials
- **Roles:** `app-user`, `app-admin`
- **MFA:** TOTP обязателен для роли `app-admin`
- **Export:** `keycloak/realm-export.json` — авто-импорт при старте контейнера

## Эндпоинты demo-app

| Метод | Путь | Описание | Доступ |
|-------|------|----------|--------|
| GET | / | Главная, кнопка Login | Публичный |
| GET | /login | Редирект в Keycloak | Публичный |
| GET | /callback | OAuth2 callback, получение токена | Публичный |
| GET | /dashboard | Защищённая страница пользователя | app-user |
| GET | /admin | Страница администратора | app-admin + MFA |
| GET | /api/whoami | JSON: claims из JWT | app-user |
| GET | /api/service-token | Демо Client Credentials flow | Публичный |
| GET | /logout | Завершение сессии в Keycloak | Авторизованный |

## Контракты между компонентами

### JWT payload (декодированный access token)
```json
{
  "sub": "uuid",
  "preferred_username": "string",
  "email": "string",
  "realm_access": { "roles": ["app-user"] },
  "exp": 1234567890,
  "iss": "http://localhost:8080/realms/iam-lab"
}
```

### Env-переменные (contracts для всех компонентов)
```
KEYCLOAK_URL=http://keycloak:8080
KEYCLOAK_REALM=iam-lab
KEYCLOAK_CLIENT_ID=demo-app
KEYCLOAK_CLIENT_SECRET=  # для service-client
APP_SECRET_KEY=          # для подписи сессий FastAPI
```

## Acceptance criteria (Definition of Done)

- [ ] `docker-compose up` поднимает весь стек без ошибок
- [ ] Keycloak доступен на :8080, realm `iam-lab` импортирован автоматически
- [ ] Authorization Code flow работает: логин → callback → /dashboard с именем пользователя
- [ ] Роли работают: app-user видит /dashboard, не видит /admin
- [ ] app-admin видит /admin (после MFA через TOTP)
- [ ] /api/whoami возвращает корректные JWT claims
- [ ] /api/service-token возвращает access_token через Client Credentials
- [ ] JWT валидация на backend: истёкший токен → 401
- [ ] README содержит архитектурную схему и инструкцию запуска
- [ ] Нет секретов в репозитории, .env.example полный
