package service

import (
    "context"
    "fmt"
    "strconv"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/user-service/internal/auth"
    "github.com/user-service/internal/domain"
    "github.com/user-service/internal/repository"
    "go.uber.org/zap"
    "golang.org/x/oauth2"
    "gorm.io/gorm"
)

// OAuthService предоставляет бизнес-логику для OAuth2 авторизации
type OAuthService struct {
    userRepo         repository.UserRepository
    oauthRepo        repository.OAuthRepository
    refreshTokenRepo repository.RefreshTokenRepository
    jwtService       *auth.JWTService
    oauthAuthService *auth.OAuthService
    txManager        repository.TransactionManager
    logger           *zap.Logger
}

// NewOAuthService создает новый OAuthService
func NewOAuthService(
    userRepo repository.UserRepository,
    oauthRepo repository.OAuthRepository,
    refreshTokenRepo repository.RefreshTokenRepository,
    jwtService *auth.JWTService,
    oauthAuthService *auth.OAuthService,
    txManager repository.TransactionManager,
    logger *zap.Logger,
) *OAuthService {
    return &OAuthService{
        userRepo:         userRepo,
        oauthRepo:        oauthRepo,
        refreshTokenRepo: refreshTokenRepo,
        jwtService:       jwtService,
        oauthAuthService: oauthAuthService,
        txManager:        txManager,
        logger:           logger,
    }
}

// GetAuthURL возвращает URL для OAuth авторизации
func (s *OAuthService) GetAuthURL(provider, state string) (string, error) {
    return s.oauthAuthService.GetAuthURL(provider, state)
}

// HandleOAuthCallback обрабатывает callback от OAuth провайдера
func (s *OAuthService) HandleOAuthCallback(ctx context.Context, provider, code, state string) (*domain.TokenResponse, error) {
    s.logger.Info("Обработка OAuth callback", zap.String("provider", provider))

    var result *domain.TokenResponse
    var err error

    // Выполняем в транзакции
    txErr := s.txManager.WithTransaction(ctx, func(ctx context.Context, tx repository.Transaction) error {
        switch provider {
        case domain.ProviderGoogle, domain.ProviderGitHub:
            result, err = s.handleStandardOAuth(ctx, tx, provider, code)
        case domain.ProviderTelegram:
            return fmt.Errorf("Telegram авторизация должна обрабатываться отдельно")
        default:
            return fmt.Errorf("неподдерживаемый провайдер: %s", provider)
        }
        return err
    })

    if txErr != nil {
        return nil, txErr
    }

    return result, nil
}

// HandleTelegramAuth обрабатывает авторизацию через Telegram
func (s *OAuthService) HandleTelegramAuth(ctx context.Context, data *domain.TelegramAuthData) (*domain.TokenResponse, error) {
    s.logger.Info("Обработка Telegram авторизации", zap.Int64("telegram_id", data.ID))

    // Валидируем данные авторизации
    if err := s.oauthAuthService.ValidateTelegramAuth(data); err != nil {
        return nil, fmt.Errorf("ошибка валидации Telegram авторизации: %w", err)
    }

    var result *domain.TokenResponse
    var err error

    // Выполняем в транзакции
    txErr := s.txManager.WithTransaction(ctx, func(ctx context.Context, tx repository.Transaction) error {
        result, err = s.handleTelegramAuth(ctx, tx, data)
        return err
    })

    if txErr != nil {
        return nil, txErr
    }

    return result, nil
}

// LinkOAuthAccount привязывает OAuth аккаунт к существующему пользователю
func (s *OAuthService) LinkOAuthAccount(ctx context.Context, userID uuid.UUID, provider, code string) error {
    s.logger.Info("Привязка OAuth аккаунта", 
        zap.String("user_id", userID.String()),
        zap.String("provider", provider))

    return s.txManager.WithTransaction(ctx, func(ctx context.Context, tx repository.Transaction) error {
        userRepo := tx.GetUserRepository()
        oauthRepo := tx.GetOAuthRepository()

        // Проверяем, что пользователь существует
        user, err := userRepo.GetByID(ctx, userID)
        if err != nil {
            if err == gorm.ErrRecordNotFound {
                return fmt.Errorf("пользователь не найден")
            }
            return fmt.Errorf("ошибка получения пользователя: %w", err)
        }

        // Проверяем, что OAuth аккаунт еще не привязан
        existingAccount, err := oauthRepo.GetByProviderAndUserID(ctx, provider, userID)
        if err == nil {
            return fmt.Errorf("аккаунт %s уже привязан к пользователю", provider)
        }

        // Получаем токен и данные пользователя от провайдера
        token, err := s.oauthAuthService.ExchangeCodeForToken(ctx, provider, code)
        if err != nil {
            return fmt.Errorf("ошибка получения токена от %s: %w", provider, err)
        }

        userData, err := s.oauthAuthService.GetUserInfo(ctx, provider, token)
        if err != nil {
            return fmt.Errorf("ошибка получения данных пользователя от %s: %w", provider, err)
        }

        // Создаем OAuth аккаунт
        oauthAccount, err := s.oauthAuthService.CreateOAuthAccount(userID, provider, userData, token)
        if err != nil {
            return fmt.Errorf("ошибка создания OAuth аккаунта: %w", err)
        }

        // Проверяем, что аккаунт с таким provider_id еще не существует
        if existingByProviderID, err := oauthRepo.GetByProviderAndProviderID(ctx, provider, oauthAccount.ProviderID); err == nil {
            if existingByProviderID.UserID != userID {
                return fmt.Errorf("аккаунт %s уже привязан к другому пользователю", provider)
            }
        }

        // Сохраняем OAuth аккаунт
        if err := oauthRepo.Create(ctx, oauthAccount); err != nil {
            return fmt.Errorf("ошибка сохранения OAuth аккаунта: %w", err)
        }

        s.logger.Info("OAuth аккаунт успешно привязан",
            zap.String("user_id", userID.String()),
            zap.String("provider", provider))

        return nil
    })
}

// UnlinkOAuthAccount отвязывает OAuth аккаунт от пользователя
func (s *OAuthService) UnlinkOAuthAccount(ctx context.Context, userID uuid.UUID, provider string) error {
    s.logger.Info("Отвязка OAuth аккаунта",
        zap.String("user_id", userID.String()),
        zap.String("provider", provider))

    return s.txManager.WithTransaction(ctx, func(ctx context.Context, tx repository.Transaction) error {
        userRepo := tx.GetUserRepository()
        oauthRepo := tx.GetOAuthRepository()

        // Получаем пользователя
        user, err := userRepo.GetByID(ctx, userID)
        if err != nil {
            return fmt.Errorf("ошибка получения пользователя: %w", err)
        }

        // Получаем OAuth аккаунт
        oauthAccount, err := oauthRepo.GetByProviderAndUserID(ctx, provider, userID)
        if err != nil {
            if err == gorm.ErrRecordNotFound {
                return fmt.Errorf("OAuth аккаунт %s не найден", provider)
            }
            return fmt.Errorf("ошибка получения OAuth аккаунта: %w", err)
        }

        // Проверяем, что у пользователя есть способ авторизации
        oauthAccounts, err := oauthRepo.ListByUserID(ctx, userID)
        if err != nil {
            return fmt.Errorf("ошибка получения OAuth аккаунтов: %w", err)
        }

        // Если это единственный OAuth аккаунт и у пользователя нет пароля
        if len(oauthAccounts) == 1 && !user.HasPassword() {
            return fmt.Errorf("нельзя отвязать последний способ авторизации")
        }

        // Удаляем OAuth аккаунт
        if err := oauthRepo.Delete(ctx, oauthAccount.ID); err != nil {
            return fmt.Errorf("ошибка удаления OAuth аккаунта: %w", err)
        }

        s.logger.Info("OAuth аккаунт успешно отвязан",
            zap.String("user_id", userID.String()),
            zap.String("provider", provider))

        return nil
    })
}

// handleStandardOAuth обрабатывает стандартный OAuth flow (Google, GitHub)
func (s *OAuthService) handleStandardOAuth(ctx context.Context, tx repository.Transaction, provider, code string) (*domain.TokenResponse, error) {
    userRepo := tx.GetUserRepository()
    oauthRepo := tx.GetOAuthRepository()
    refreshTokenRepo := tx.GetRefreshTokenRepository()

    // Обмениваем код на токен
    token, err := s.oauthAuthService.ExchangeCodeForToken(ctx, provider, code)
    if err != nil {
        return nil, fmt.Errorf("ошибка обмена кода на токен: %w", err)
    }

    // Получаем информацию о пользователе
    userData, err := s.oauthAuthService.GetUserInfo(ctx, provider, token)
    if err != nil {
        return nil, fmt.Errorf("ошибка получения информации о пользователе: %w", err)
    }

    // Создаем временный OAuth аккаунт для получения данных
    tempOAuthAccount, err := s.oauthAuthService.CreateOAuthAccount(uuid.Nil, provider, userData, token)
    if err != nil {
        return nil, fmt.Errorf("ошибка обработки данных OAuth: %w", err)
    }

    // Ищем существующий OAuth аккаунт
    existingOAuth, err := oauthRepo.GetByProviderAndProviderID(ctx, provider, tempOAuthAccount.ProviderID)
    if err != nil && err != gorm.ErrRecordNotFound {
        return nil, fmt.Errorf("ошибка поиска OAuth аккаунта: %w", err)
    }

    var user *domain.User

    if existingOAuth != nil {
        // OAuth аккаунт уже существует - используем связанного пользователя
        user = &existingOAuth.User

        // Обновляем токены OAuth аккаунта
        existingOAuth.AccessToken = token.AccessToken
        if token.RefreshToken != "" {
            existingOAuth.RefreshToken = &token.RefreshToken
        }
        if !token.Expiry.IsZero() {
            existingOAuth.ExpiresAt = &token.Expiry
        }

        if err := oauthRepo.Update(ctx, existingOAuth); err != nil {
            return nil, fmt.Errorf("ошибка обновления OAuth аккаунта: %w", err)
        }
    } else {
        // Создаем нового пользователя
        user, err = s.createUserFromOAuth(ctx, userRepo, tempOAuthAccount)
        if err != nil {
            return nil, err
        }

        // Создаем OAuth аккаунт
        tempOAuthAccount.UserID = user.ID
        if err := oauthRepo.Create(ctx, tempOAuthAccount); err != nil {
            return nil, fmt.Errorf("ошибка создания OAuth аккаунта: %w", err)
        }
    }

    // Генерируем токены
    tokenPair, err := s.jwtService.GenerateTokenPair(user)
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации токенов: %w", err)
    }

    // Сохраняем refresh токен
    refreshToken := &domain.RefreshToken{
        UserID:    user.ID,
        Token:     tokenPair.RefreshToken,
        ExpiresAt: time.Now().Add(24 * 7 * time.Hour),
    }

    if err := refreshTokenRepo.Create(ctx, refreshToken); err != nil {
        return nil, fmt.Errorf("ошибка сохранения refresh токена: %w", err)
    }

    // Обновляем время последнего входа
    if err := userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
        s.logger.Warn("Ошибка обновления времени входа", zap.Error(err))
    }

    return &domain.TokenResponse{
        AccessToken:  tokenPair.AccessToken,
        RefreshToken: tokenPair.RefreshToken,
        TokenType:    tokenPair.TokenType,
        ExpiresIn:    tokenPair.ExpiresIn,
        ExpiresAt:    tokenPair.ExpiresAt,
    }, nil
}

// handleTelegramAuth обрабатывает авторизацию через Telegram
func (s *OAuthService) handleTelegramAuth(ctx context.Context, tx repository.Transaction, data *domain.TelegramAuthData) (*domain.TokenResponse, error) {
    userRepo := tx.GetUserRepository()
    oauthRepo := tx.GetOAuthRepository()
    refreshTokenRepo := tx.GetRefreshTokenRepository()

    providerID := strconv.FormatInt(data.ID, 10)

    // Ищем существующий OAuth аккаунт
    existingOAuth, err := oauthRepo.GetByProviderAndProviderID(ctx, domain.ProviderTelegram, providerID)
    if err != nil && err != gorm.ErrRecordNotFound {
        return nil, fmt.Errorf("ошибка поиска OAuth аккаунта: %w", err)
    }

    var user *domain.User

    if existingOAuth != nil {
        // OAuth аккаунт уже существует
        user = &existingOAuth.User
    } else {
        // Создаем нового пользователя
        user, err = s.createUserFromTelegram(ctx, userRepo, data)
        if err != nil {
            return nil, err
        }

        // Создаем OAuth аккаунт
        oauthAccount, err := s.oauthAuthService.CreateOAuthAccount(user.ID, domain.ProviderTelegram, data, nil)
        if err != nil {
            return nil, fmt.Errorf("ошибка создания OAuth аккаунта: %w", err)
        }

        if err := oauthRepo.Create(ctx, oauthAccount); err != nil {
            return nil, fmt.Errorf("ошибка сохранения OAuth аккаунта: %w", err)
        }
    }

    // Генерируем токены
    tokenPair, err := s.jwtService.GenerateTokenPair(user)
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации токенов: %w", err)
    }

    // Сохраняем refresh токен
    refreshToken := &domain.RefreshToken{
        UserID:    user.ID,
        Token:     tokenPair.RefreshToken,
        ExpiresAt: time.Now().Add(24 * 7 * time.Hour),
    }

    if err := refreshTokenRepo.Create(ctx, refreshToken); err != nil {
        return nil, fmt.Errorf("ошибка сохранения refresh токена: %w", err)
    }

    // Обновляем время последнего входа
    if err := userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
        s.logger.Warn("Ошибка обновления времени входа", zap.Error(err))
    }

    return &domain.TokenResponse{
        AccessToken:  tokenPair.AccessToken,
        RefreshToken: tokenPair.RefreshToken,
        TokenType:    tokenPair.TokenType,
        ExpiresIn:    tokenPair.ExpiresIn,
        ExpiresAt:    tokenPair.ExpiresAt,
    }, nil
}

// createUserFromOAuth создает пользователя из данных OAuth
func (s *OAuthService) createUserFromOAuth(ctx context.Context, userRepo repository.UserRepository, oauthAccount *domain.OAuthAccount) (*domain.User, error) {
    email := strings.ToLower(oauthAccount.Email)
    username := oauthAccount.Username

    // Если username пустой, генерируем из email
    if username == "" {
        parts := strings.Split(email, "@")
        if len(parts) > 0 {
            username = parts[0]
        }
    }

    // Убеждаемся, что username уникален
    baseUsername := username
    counter := 1
    for {
        exists, err := userRepo.ExistsByUsername(ctx, username)
        if err != nil {
            return nil, fmt.Errorf("ошибка проверки username: %w", err)
        }
        if !exists {
            break
        }
        username = fmt.Sprintf("%s%d", baseUsername, counter)
        counter++
    }

    // Проверяем email на уникальность
    if email != "" {
        exists, err := userRepo.ExistsByEmail(ctx, email)
        if err != nil {
            return nil, fmt.Errorf("ошибка проверки email: %w", err)
        }
        if exists {
            return nil, fmt.Errorf("пользователь с email %s уже существует", email)
        }
    }

    // Создаем пользователя
    user := &domain.User{
        Email:      email,
        Username:   username,
        FirstName:  oauthAccount.Username, // Используем username как FirstName по умолчанию
        LastName:   "",
        Avatar:     &oauthAccount.Avatar,
        IsActive:   true,
        IsVerified: true, // OAuth пользователи считаются верифицированными
    }

    if err := userRepo.Create(ctx, user); err != nil {
        return nil, fmt.Errorf("ошибка создания пользователя: %w", err)
    }

    return user, nil
}

// createUserFromTelegram создает пользователя из данных Telegram
func (s *OAuthService) createUserFromTelegram(ctx context.Context, userRepo repository.UserRepository, data *domain.TelegramAuthData) (*domain.User, error) {
    username := data.Username
    if username == "" {
        username = fmt.Sprintf("user_%d", data.ID)
    }

    // Убеждаемся, что username уникален
    baseUsername := username
    counter := 1
    for {
        exists, err := userRepo.ExistsByUsername(ctx, username)
        if err != nil {
            return nil, fmt.Errorf("ошибка проверки username: %w", err)
        }
        if !exists {
            break
        }
        username = fmt.Sprintf("%s%d", baseUsername, counter)
        counter++
    }

    firstName := data.FirstName
    lastName := data.LastName

    user := &domain.User{
        Username:   username,
        FirstName:  firstName,
        LastName:   lastName,
        IsActive:   true,
        IsVerified: true,
    }

    if data.PhotoURL != "" {
        user.Avatar = &data.PhotoURL
    }

    if err := userRepo.Create(ctx, user); err != nil {
        return nil, fmt.Errorf("ошибка создания пользователя: %w", err)
    }

    return user, nil
}
