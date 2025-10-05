package main

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/user-service/internal/app"
    "github.com/user-service/internal/config"
    "github.com/user-service/pkg/logger"
    "go.uber.org/zap"
)

// @title User Service API
// @version 1.0
// @description Микросервис управления пользователями с OAuth2 авторизацией
// @contact.name API Support
// @contact.email support@example.com
// @host localhost:8080
// @BasePath /api/v1
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
    // Инициализация конфигурации
    cfg, err := config.Load()
    if err != nil {
        panic(fmt.Sprintf("Ошибка загрузки конфигурации: %v", err))
    }

    // Инициализация логгера
    log, err := logger.New(cfg.Logger.Level, cfg.Logger.Format)
    if err != nil {
        panic(fmt.Sprintf("Ошибка инициализации логгера: %v", err))
    }
    defer log.Sync()

    log.Info("Запуск User Service",
        zap.String("version", "1.0.0"),
        zap.String("environment", cfg.Environment),
        zap.String("port", cfg.HTTP.Port),
    )

    // Создание и запуск приложения
    application, err := app.New(cfg, log)
    if err != nil {
        log.Fatal("Ошибка создания приложения", zap.Error(err))
    }

    // Graceful shutdown
    go func() {
        if err := application.Start(); err != nil && err != http.ErrServerClosed {
            log.Fatal("Ошибка запуска HTTP сервера", zap.Error(err))
        }
    }()

    log.Info("User Service успешно запущен",
        zap.String("port", cfg.HTTP.Port),
        zap.String("swagger", fmt.Sprintf("http://localhost:%s/swagger/index.html", cfg.HTTP.Port)),
    )

    // Ожидание сигналов завершения
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
    <-quit

    log.Info("Получен сигнал завершения, начинаем graceful shutdown...")

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    if err := application.Shutdown(ctx); err != nil {
        log.Error("Ошибка graceful shutdown", zap.Error(err))
        os.Exit(1)
    }

    log.Info("User Service успешно остановлен")
}
