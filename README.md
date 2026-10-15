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

JWT_SECRET=change-me-in-production
JWT_ACCESS_TOKEN_TTL_MINUTES=15

SERVER__HOST=0.0.0.0
SERVER__PORT=5000
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

Базовый путь: `/api/v1`. Пока реализована одна ручка.

### `POST /api/v1/user` - регистрация

**Запрос:**

```bash
curl -X POST http://localhost:5200/api/v1/user \
  -H 'Content-Type: application/json' \
  -d '{"username":"qotofey","password":"Qwerty123!"}'
```

### Планируется

- POST /api/v1/user/session - аутентификация
- PUT /api/v1/user/session - обновление сессии (refresh)
- DELETE /api/v1/user/session - закрытие сессии
- GET /api/v1/user - профиль текущего пользователя
- PATCH /api/v1/user - обновление профиля
- DELETE /api/v1/user - мягкое удаление
- POST /api/v1/user/restore - восстановление
- POST /api/v1/user/password - смена пароля
