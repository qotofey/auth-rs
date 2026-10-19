# auth-rs

Rust-сервис аутентификации: регистрация пользователей, хеширование паролей Argon2id, JWT-сессии и refresh-токены. Хранилище - PostgreSQL (SQLx), HTTP-слой - Axum.

## Стек

- **Rust** (edition 2024)
- **Axum** 0.8 - HTTP-сервер
- **SQLx** 0.8 - PostgreSQL, async, миграции
- **Argon2id** - хеширование паролей (`argon2` 0.5)
- **jsonwebtoken** 10 - JWT (HS256)
- **config + dotenvy** - конфигурация из env-переменных
- **validator** - валидация входных данных (в процессе внедрения)

## Запуск

### Требования

- Rust 1.85+ (`edition 2024`)
- PostgreSQL 15+

### Конфигурация

Скопируйте пример и заполните:

```bash
cp .env.example .env
```

Переменные окружения (двойное подчёркивание __ - разделитель вложенности):

```
DATABASE_URL=postgres://user:password@localhost:5432/auth_dev
DATABASE_MAX_CONNECTIONS=5

ARGON2__MEMORY_COST=19456
ARGON2__TIME_COST=2
ARGON2__PARALLELISM=1

JWT_SECRET=change-me-in-production
JWT_ACCESS_TOKEN_TTL_MINUTES=15

SERVER__HOST=0.0.0.0
SERVER__PORT=5200
```

### Миграции

```bash
cargo install sqlx-cli --no-default-features --features postgres
export DATABASE_URL="postgres://user:password@localhost:5432/auth_dev"
sqlx migrate run
```

### Запуск

```bash
cargo run
```

Сервер слушает хост и порт из SERVER__HOST / SERVER__PORT.

## API

Базовый путь: `/api/v1`.

### Формат JSON:API 1.1

- Content-Type запросов: только `application/vnd.api+json` (case-insensitive, с параметрами типа `; charset=utf-8`). Иначе — 415 Unsupported Media Type в JSON:API-формате.
- Content-Type ответов: всегда `application/vnd.api+json`.
- Все ключи — camelCase (`firstName`, `accessToken`, `refreshToken`).
- Ошибки: `{"errors": [{"status": "...", "detail": "...", "source": {"pointer": "..."}}]}`.
- Успех: `{"data": {...}, "meta": {...}}` или `{"meta": {...}}`.

### `POST /api/v1/user` - регистрация

**Запрос:**

```bash
curl -i -X POST http://localhost:5200/api/v1/user \
  -H 'Content-Type: application/vnd.api+json' \
  -d '{
    "data": {
      "type": "users",
      "attributes": {
        "username": "qotofey",
        "password": "Qwerty123!",
        "firstName": "Иван",
        "middleName": "Иванович",
        "lastName": "Иванов",
        "birthdate": "1990-05-15",
        "gender": "male"
      }
    }
  }'
```

## `POST /api/v1/user/session` - аутентификация

**Запрос:**

```bash
curl -i -X POST http://localhost:5200/api/v1/user/session \
  -H 'Content-Type: application/vnd.api+json' \
  -d '{
    "data": {
      "type": "sessions",
      "attributes": {
        "login": "qotofey",
        "password": "Qwerty123!"
      }
    }
  }'
```

**Ответ 201:**

```bash
{
  "data": {
    "type": "sessions",
    "id": "<user_id>"
  },
  "meta": {
    "accessToken": "<jwt>",
    "refreshToken": "<opaque>"
  }
}
```

### Планируется

- `PUT /api/v1/user/session` - обновление сессии (refresh)
- `DELETE /api/v1/user/sessionq` - закрытие сессии
- `GET /api/v1/user` - профиль текущего пользователя
- `PATCH /api/v1/user` - обновление профиля
- `DELETE /api/v1/user` - мягкое удаление
- `POST /api/v1/user/restore` - восстановление
- `POST /api/v1/user/password` - смена пароля
