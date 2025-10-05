# User Service - Senior-Level Go Microservice

Современный микросервис управления пользователями на Go с OAuth2 интеграцией.

## Особенности

- Clean Architecture
- JWT аутентификация  
- OAuth2 (Google, GitHub, Telegram)
- PostgreSQL + Redis
- Docker контейнеризация
- Swagger документация
- Graceful shutdown

## Быстрый старт

1. Настройка:
```bash
cp .env.example .env
```

2. Запуск с Docker:
```bash
make docker-up
```

3. API документация:
http://localhost:8080/swagger/index.html

## API Endpoints

### Аутентификация
- POST /api/v1/auth/login - Вход
- POST /api/v1/auth/refresh - Обновление токена  
- POST /api/v1/auth/logout - Выход

### Пользователи
- POST /api/v1/users - Регистрация
- GET /api/v1/users/me - Профиль
- PUT /api/v1/users/me - Обновление
- DELETE /api/v1/users/me - Удаление

### OAuth
- GET /api/v1/oauth/{provider}/auth - URL авторизации
- GET /api/v1/oauth/{provider}/callback - Callback
- POST /api/v1/oauth/telegram/auth - Telegram авторизация

## Технологии

- Go 1.23
- Gin (HTTP framework)
- GORM (ORM)
- PostgreSQL
- Redis  
- JWT
- Docker
- Swagger

## Архитектура

```
cmd/server/           # Точка входа
internal/
  ├── app/           # Инициализация
  ├── auth/          # JWT/OAuth сервисы
  ├── config/        # Конфигурация
  ├── domain/        # Модели
  ├── handler/       # HTTP handlers
  ├── middleware/    # Middleware
  ├── repository/    # Data access
  └── service/       # Бизнес-логика
pkg/
  ├── logger/        # Логирование
  └── postgres/      # DB клиент
```

## Разработка

```bash
# Тесты
make test

# Сборка
make build  

# Запуск
make run

# Docker
make docker-build
make docker-up
```
