# Сборка приложения
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Копируем go.mod и go.sum для кэширования зависимостей
COPY go.mod go.sum ./
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение с оптимизациями для production
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build     -ldflags='-w -s -extldflags "-static"'     -a -installsuffix cgo     -o main ./cmd/server

# Финальный образ
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Создаем пользователя для безопасности
RUN adduser -D -s /bin/sh appuser

# Копируем собранное приложение
COPY --from=builder /app/main .
COPY --from=builder /app/migrations ./migrations/

# Устанавливаем владельца
RUN chown -R appuser:appuser /root/

USER appuser

EXPOSE 8080

CMD ["./main"]
