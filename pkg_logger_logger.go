package logger

import (
    "strings"

    "go.uber.org/zap"
    "go.uber.org/zap/zapcore"
)

// New создает новый logger с указанным уровнем и форматом
func New(level, format string) (*zap.Logger, error) {
    // Парсинг уровня логирования
    var zapLevel zapcore.Level
    switch strings.ToLower(level) {
    case "debug":
        zapLevel = zapcore.DebugLevel
    case "info":
        zapLevel = zapcore.InfoLevel
    case "warn", "warning":
        zapLevel = zapcore.WarnLevel
    case "error":
        zapLevel = zapcore.ErrorLevel
    case "fatal":
        zapLevel = zapcore.FatalLevel
    default:
        zapLevel = zapcore.InfoLevel
    }

    // Конфигурация в зависимости от формата
    var config zap.Config

    switch strings.ToLower(format) {
    case "json":
        config = zap.NewProductionConfig()
        config.Level = zap.NewAtomicLevelAt(zapLevel)
        config.EncoderConfig.TimeKey = "timestamp"
        config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
        config.EncoderConfig.LevelKey = "level"
        config.EncoderConfig.EncodeLevel = zapcore.LowercaseLevelEncoder
        config.EncoderConfig.CallerKey = "caller"
        config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
        config.EncoderConfig.MessageKey = "message"
        config.EncoderConfig.StacktraceKey = "stacktrace"

    case "console":
        config = zap.NewDevelopmentConfig()
        config.Level = zap.NewAtomicLevelAt(zapLevel)
        config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
        config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
        config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

    default:
        // По умолчанию используем JSON формат
        config = zap.NewProductionConfig()
        config.Level = zap.NewAtomicLevelAt(zapLevel)
    }

    // Отключаем sampling для debug уровня
    if zapLevel == zapcore.DebugLevel {
        config.Sampling = nil
    }

    logger, err := config.Build(zap.AddCallerSkip(1))
    if err != nil {
        return nil, err
    }

    return logger, nil
}

// NewNoop создает no-op logger (используется в тестах)
func NewNoop() *zap.Logger {
    return zap.NewNop()
}

// NewForTesting создает logger для тестов
func NewForTesting() *zap.Logger {
    config := zap.NewDevelopmentConfig()
    config.Level = zap.NewAtomicLevelAt(zapcore.DebugLevel)
    logger, _ := config.Build()
    return logger
}
