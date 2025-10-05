package config

import (
    "fmt"
    "os"
    "time"

    "github.com/spf13/viper"
)

// Config содержит всю конфигурацию приложения
type Config struct {
    Environment string       `mapstructure:"environment"`
    HTTP        HTTPConfig   `mapstructure:"http"`
    Database    DBConfig     `mapstructure:"database"`
    Redis       RedisConfig  `mapstructure:"redis"`
    Logger      LoggerConfig `mapstructure:"logger"`
    OAuth       OAuthConfig  `mapstructure:"oauth"`
    JWT         JWTConfig    `mapstructure:"jwt"`
}

type HTTPConfig struct {
    Port            string        `mapstructure:"port"`
    ReadTimeout     time.Duration `mapstructure:"read_timeout"`
    WriteTimeout    time.Duration `mapstructure:"write_timeout"`
    IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
    ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
    MaxRequestSize  int64         `mapstructure:"max_request_size"`
}

type DBConfig struct {
    Host            string        `mapstructure:"host"`
    Port            string        `mapstructure:"port"`
    User            string        `mapstructure:"user"`
    Password        string        `mapstructure:"password"`
    DBName          string        `mapstructure:"dbname"`
    SSLMode         string        `mapstructure:"ssl_mode"`
    MaxOpenConns    int           `mapstructure:"max_open_conns"`
    MaxIdleConns    int           `mapstructure:"max_idle_conns"`
    ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
    Host         string        `mapstructure:"host"`
    Port         string        `mapstructure:"port"`
    Password     string        `mapstructure:"password"`
    DB           int           `mapstructure:"db"`
    DialTimeout  time.Duration `mapstructure:"dial_timeout"`
    ReadTimeout  time.Duration `mapstructure:"read_timeout"`
    WriteTimeout time.Duration `mapstructure:"write_timeout"`
    PoolSize     int           `mapstructure:"pool_size"`
    MinIdleConns int           `mapstructure:"min_idle_conns"`
}

type LoggerConfig struct {
    Level  string `mapstructure:"level"`
    Format string `mapstructure:"format"` // json или console
}

type OAuthConfig struct {
    Google   OAuthProvider `mapstructure:"google"`
    GitHub   OAuthProvider `mapstructure:"github"`
    Telegram TelegramAuth  `mapstructure:"telegram"`
}

type OAuthProvider struct {
    ClientID     string `mapstructure:"client_id"`
    ClientSecret string `mapstructure:"client_secret"`
    RedirectURL  string `mapstructure:"redirect_url"`
    Scopes       []string `mapstructure:"scopes"`
}

type TelegramAuth struct {
    BotToken string `mapstructure:"bot_token"`
    BotName  string `mapstructure:"bot_name"`
}

type JWTConfig struct {
    SecretKey      string        `mapstructure:"secret_key"`
    AccessExpTime  time.Duration `mapstructure:"access_exp_time"`
    RefreshExpTime time.Duration `mapstructure:"refresh_exp_time"`
    Issuer         string        `mapstructure:"issuer"`
}

// Load загружает конфигурацию из файла и переменных окружения
func Load() (*Config, error) {
    // Установка значений по умолчанию
    setDefaults()

    // Настройка viper
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.AddConfigPath("./configs")
    viper.AddConfigPath("/etc/user-service/")

    // Автоматическое чтение переменных окружения
    viper.AutomaticEnv()

    // Чтение конфигурационного файла (опционально)
    if err := viper.ReadInConfig(); err != nil {
        if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
            return nil, fmt.Errorf("ошибка чтения конфигурационного файла: %w", err)
        }
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, fmt.Errorf("ошибка десериализации конфигурации: %w", err)
    }

    // Валидация критичных параметров
    if err := validateConfig(&config); err != nil {
        return nil, fmt.Errorf("ошибка валидации конфигурации: %w", err)
    }

    return &config, nil
}

func setDefaults() {
    viper.SetDefault("environment", "development")

    // HTTP defaults
    viper.SetDefault("http.port", "8080")
    viper.SetDefault("http.read_timeout", 15*time.Second)
    viper.SetDefault("http.write_timeout", 15*time.Second)
    viper.SetDefault("http.idle_timeout", 60*time.Second)
    viper.SetDefault("http.shutdown_timeout", 10*time.Second)
    viper.SetDefault("http.max_request_size", 32*1024*1024) // 32MB

    // Database defaults
    viper.SetDefault("database.host", "localhost")
    viper.SetDefault("database.port", "5432")
    viper.SetDefault("database.user", "postgres")
    viper.SetDefault("database.password", "postgres")
    viper.SetDefault("database.dbname", "user_service")
    viper.SetDefault("database.ssl_mode", "disable")
    viper.SetDefault("database.max_open_conns", 25)
    viper.SetDefault("database.max_idle_conns", 5)
    viper.SetDefault("database.conn_max_lifetime", 5*time.Minute)

    // Redis defaults
    viper.SetDefault("redis.host", "localhost")
    viper.SetDefault("redis.port", "6379")
    viper.SetDefault("redis.db", 0)
    viper.SetDefault("redis.dial_timeout", 5*time.Second)
    viper.SetDefault("redis.read_timeout", 3*time.Second)
    viper.SetDefault("redis.write_timeout", 3*time.Second)
    viper.SetDefault("redis.pool_size", 10)
    viper.SetDefault("redis.min_idle_conns", 3)

    // Logger defaults
    viper.SetDefault("logger.level", "info")
    viper.SetDefault("logger.format", "json")

    // JWT defaults
    viper.SetDefault("jwt.secret_key", "your-secret-key-change-in-production")
    viper.SetDefault("jwt.access_exp_time", 15*time.Minute)
    viper.SetDefault("jwt.refresh_exp_time", 24*7*time.Hour)
    viper.SetDefault("jwt.issuer", "user-service")

    // OAuth defaults
    viper.SetDefault("oauth.google.scopes", []string{"openid", "profile", "email"})
    viper.SetDefault("oauth.github.scopes", []string{"user:email"})
}

func validateConfig(cfg *Config) error {
    if cfg.JWT.SecretKey == "your-secret-key-change-in-production" && cfg.Environment == "production" {
        return fmt.Errorf("JWT secret key должен быть изменен для production среды")
    }

    if cfg.Database.Host == "" {
        return fmt.Errorf("database.host не может быть пустым")
    }

    return nil
}

// DSN возвращает строку подключения к PostgreSQL
func (db *DBConfig) DSN() string {
    return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
        db.Host, db.Port, db.User, db.Password, db.DBName, db.SSLMode)
}

// RedisAddr возвращает адрес Redis
func (r *RedisConfig) RedisAddr() string {
    return fmt.Sprintf("%s:%s", r.Host, r.Port)
}
