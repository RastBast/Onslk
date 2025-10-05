package auth

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
    "github.com/user-service/internal/config"
    "github.com/user-service/internal/domain"
)

// JWTService предоставляет функциональность для работы с JWT токенами
type JWTService struct {
    config *config.JWTConfig
}

// NewJWTService создает новый JWTService
func NewJWTService(cfg *config.JWTConfig) *JWTService {
    return &JWTService{
        config: cfg,
    }
}

// Claims представляет claims для JWT токена
type Claims struct {
    UserID    uuid.UUID `json:"user_id"`
    Username  string    `json:"username"`
    Email     string    `json:"email"`
    IsActive  bool      `json:"is_active"`
    TokenType string    `json:"token_type"` // access или refresh
    jwt.RegisteredClaims
}

// TokenPair представляет пару access и refresh токенов
type TokenPair struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresIn    int64     `json:"expires_in"`
    ExpiresAt    time.Time `json:"expires_at"`
}

// GenerateTokenPair генерирует пару токенов для пользователя
func (s *JWTService) GenerateTokenPair(user *domain.User) (*TokenPair, error) {
    now := time.Now()
    accessExpTime := now.Add(s.config.AccessExpTime)
    refreshExpTime := now.Add(s.config.RefreshExpTime)

    // Генерируем access token
    accessClaims := &Claims{
        UserID:    user.ID,
        Username:  user.Username,
        Email:     user.Email,
        IsActive:  user.IsActive,
        TokenType: "access",
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(accessExpTime),
            IssuedAt:  jwt.NewNumericDate(now),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    s.config.Issuer,
            Subject:   user.ID.String(),
            ID:        uuid.New().String(),
        },
    }

    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, err := accessToken.SignedString([]byte(s.config.SecretKey))
    if err != nil {
        return nil, fmt.Errorf("ошибка создания access токена: %w", err)
    }

    // Генерируем refresh token (простая случайная строка)
    refreshToken, err := s.generateRandomToken()
    if err != nil {
        return nil, fmt.Errorf("ошибка создания refresh токена: %w", err)
    }

    return &TokenPair{
        AccessToken:  accessTokenString,
        RefreshToken: refreshToken,
        TokenType:    "Bearer",
        ExpiresIn:    int64(s.config.AccessExpTime.Seconds()),
        ExpiresAt:    accessExpTime,
    }, nil
}

// ValidateAccessToken валидирует access токен и возвращает claims
func (s *JWTService) ValidateAccessToken(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        // Проверяем метод подписи
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("неожиданный метод подписи: %v", token.Header["alg"])
        }
        return []byte(s.config.SecretKey), nil
    })

    if err != nil {
        return nil, fmt.Errorf("ошибка парсинга токена: %w", err)
    }

    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, fmt.Errorf("невалидный токен")
    }

    // Проверяем тип токена
    if claims.TokenType != "access" {
        return nil, fmt.Errorf("неверный тип токена")
    }

    // Проверяем активность пользователя
    if !claims.IsActive {
        return nil, fmt.Errorf("пользователь неактивен")
    }

    return claims, nil
}

// ExtractTokenFromBearer извлекает токен из Authorization header
func (s *JWTService) ExtractTokenFromBearer(authHeader string) (string, error) {
    const bearerPrefix = "Bearer "

    if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
        return "", fmt.Errorf("неверный формат Authorization header")
    }

    return authHeader[len(bearerPrefix):], nil
}

// generateRandomToken генерирует случайный токен для refresh token
func (s *JWTService) generateRandomToken() (string, error) {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// GetTokenRemainingTime возвращает оставшееся время жизни токена
func (s *JWTService) GetTokenRemainingTime(claims *Claims) time.Duration {
    if claims.ExpiresAt == nil {
        return 0
    }
    return time.Until(claims.ExpiresAt.Time)
}

// IsTokenExpired проверяет, истек ли токен
func (s *JWTService) IsTokenExpired(claims *Claims) bool {
    if claims.ExpiresAt == nil {
        return true
    }
    return time.Now().After(claims.ExpiresAt.Time)
}
