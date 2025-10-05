package postgres

import (
    "fmt"
    "time"

    "github.com/user-service/internal/config"
    "github.com/user-service/internal/domain"
    "go.uber.org/zap"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"
)

// Client представляет клиент для работы с PostgreSQL
type Client struct {
    db     *gorm.DB
    logger *zap.Logger
}

// New создает новый PostgreSQL клиент
func New(cfg *config.DBConfig, log *zap.Logger) (*Client, error) {
    // Настройка GORM logger
    gormLogger := logger.New(
        &zapLogWriter{logger: log},
        logger.Config{
            SlowThreshold:             time.Second,   // Медленные SQL запросы
            LogLevel:                  logger.Info,   // Уровень логирования
            IgnoreRecordNotFoundError: true,          // Игнорировать ошибки "record not found"
            Colorful:                  false,         // Отключить цвета в продакшене
        },
    )

    // Конфигурация GORM
    gormConfig := &gorm.Config{
        Logger: gormLogger,
        NowFunc: func() time.Time {
            return time.Now().UTC()
        },
        PrepareStmt: true, // Подготавливать SQL statements для лучшей производительности
    }

    // Подключение к базе данных
    db, err := gorm.Open(postgres.Open(cfg.DSN()), gormConfig)
    if err != nil {
        return nil, fmt.Errorf("ошибка подключения к БД: %w", err)
    }

    // Настройка connection pool
    sqlDB, err := db.DB()
    if err != nil {
        return nil, fmt.Errorf("ошибка получения SQL DB: %w", err)
    }

    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
    sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

    // Проверка подключения
    if err := sqlDB.Ping(); err != nil {
        return nil, fmt.Errorf("ошибка ping БД: %w", err)
    }

    client := &Client{
        db:     db,
        logger: log,
    }

    // Автоматическая миграция схемы (только для разработки)
    // В продакшене лучше использовать отдельные инструменты миграции
    if err := client.AutoMigrate(); err != nil {
        log.Warn("Ошибка автомиграции", zap.Error(err))
    }

    log.Info("Подключение к PostgreSQL установлено",
        zap.String("host", cfg.Host),
        zap.String("port", cfg.Port),
        zap.String("database", cfg.DBName),
    )

    return client, nil
}

// DB возвращает экземпляр GORM DB
func (c *Client) DB() *gorm.DB {
    return c.db
}

// Close закрывает подключение к базе данных
func (c *Client) Close() error {
    sqlDB, err := c.db.DB()
    if err != nil {
        return err
    }

    c.logger.Info("Закрытие подключения к PostgreSQL")
    return sqlDB.Close()
}

// AutoMigrate выполняет автоматическую миграцию схемы
func (c *Client) AutoMigrate() error {
    c.logger.Info("Выполнение автомиграции схемы БД")

    return c.db.AutoMigrate(
        &domain.User{},
        &domain.OAuthAccount{},
        &domain.RefreshToken{},
        &domain.UserRole{},
        &domain.UserRoleAssignment{},
    )
}

// Health проверяет состояние подключения к БД
func (c *Client) Health() error {
    sqlDB, err := c.db.DB()
    if err != nil {
        return err
    }
    return sqlDB.Ping()
}

// GetStats возвращает статистику подключения
func (c *Client) GetStats() (map[string]interface{}, error) {
    sqlDB, err := c.db.DB()
    if err != nil {
        return nil, err
    }

    stats := sqlDB.Stats()
    return map[string]interface{}{
        "max_open_connections":   stats.MaxOpenConnections,
        "open_connections":       stats.OpenConnections,
        "in_use":                stats.InUse,
        "idle":                  stats.Idle,
        "wait_count":            stats.WaitCount,
        "wait_duration":         stats.WaitDuration.String(),
        "max_idle_closed":       stats.MaxIdleClosed,
        "max_idle_time_closed":  stats.MaxIdleTimeClosed,
        "max_lifetime_closed":   stats.MaxLifetimeClosed,
    }, nil
}

// zapLogWriter адаптер для использования zap logger с GORM
type zapLogWriter struct {
    logger *zap.Logger
}

// Printf реализует интерфейс logger.Writer для GORM
func (z *zapLogWriter) Printf(format string, args ...interface{}) {
    z.logger.Info(fmt.Sprintf(format, args...))
}
