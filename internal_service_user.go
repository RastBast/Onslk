package service

import (
    "context"
    "fmt"
    "math"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/user-service/internal/auth"
    "github.com/user-service/internal/domain"
    "github.com/user-service/internal/repository"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

// UserService предоставляет бизнес-логику для работы с пользователями
type UserService struct {
    userRepo         repository.UserRepository
    oauthRepo        repository.OAuthRepository
    refreshTokenRepo repository.RefreshTokenRepository
    jwtService       *auth.JWTService
    oauthService     *auth.OAuthService
    txManager        repository.TransactionManager
    logger           *zap.Logger
}

// NewUserService создает новый UserService
func NewUserService(
    userRepo repository.UserRepository,
    oauthRepo repository.OAuthRepository,
    refreshTokenRepo repository.RefreshTokenRepository,
    jwtService *auth.JWTService,
    oauthService *auth.OAuthService,
    txManager repository.TransactionManager,
    logger *zap.Logger,
) *UserService {
    return &UserService{
        userRepo:         userRepo,
        oauthRepo:        oauthRepo,
        refreshTokenRepo: refreshTokenRepo,
        jwtService:       jwtService,
        oauthService:     oauthService,
        txManager:        txManager,
        logger:           logger,
    }
}

// CreateUser создает нового пользователя с паролем
func (s *UserService) CreateUser(ctx context.Context, req *domain.CreateUserRequest) (*domain.UserResponse, error) {
    s.logger.Info("Создание пользователя", zap.String("email", req.Email), zap.String("username", req.Username))

    // Проверяем уникальность email и username
    if exists, err := s.userRepo.ExistsByEmail(ctx, req.Email); err != nil {
        return nil, fmt.Errorf("ошибка проверки email: %w", err)
    } else if exists {
        return nil, fmt.Errorf("пользователь с email %s уже существует", req.Email)
    }

    if exists, err := s.userRepo.ExistsByUsername(ctx, req.Username); err != nil {
        return nil, fmt.Errorf("ошибка проверки username: %w", err)
    } else if exists {
        return nil, fmt.Errorf("пользователь с username %s уже существует", req.Username)
    }

    // Создаем пользователя
    user := &domain.User{
        Email:     strings.ToLower(req.Email),
        Username:  req.Username,
        FirstName: req.FirstName,
        LastName:  req.LastName,
        IsActive:  true,
    }

    // Устанавливаем пароль
    if err := user.SetPassword(req.Password); err != nil {
        return nil, fmt.Errorf("ошибка установки пароля: %w", err)
    }

    // Сохраняем в базе данных
    if err := s.userRepo.Create(ctx, user); err != nil {
        s.logger.Error("Ошибка создания пользователя в БД", zap.Error(err))
        return nil, fmt.Errorf("ошибка создания пользователя: %w", err)
    }

    s.logger.Info("Пользователь успешно создан", zap.String("user_id", user.ID.String()))

    response := user.ToResponse()
    return &response, nil
}

// GetUser получает пользователя по ID
func (s *UserService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.UserResponse, error) {
    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("пользователь не найден")
        }
        return nil, fmt.Errorf("ошибка получения пользователя: %w", err)
    }

    response := user.ToResponse()
    return &response, nil
}

// UpdateUser обновляет данные пользователя
func (s *UserService) UpdateUser(ctx context.Context, userID uuid.UUID, req *domain.UpdateUserRequest) (*domain.UserResponse, error) {
    s.logger.Info("Обновление пользователя", zap.String("user_id", userID.String()))

    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("пользователь не найден")
        }
        return nil, fmt.Errorf("ошибка получения пользователя: %w", err)
    }

    // Обновляем поля
    if req.FirstName != nil {
        user.FirstName = *req.FirstName
    }
    if req.LastName != nil {
        user.LastName = *req.LastName
    }
    if req.Avatar != nil {
        user.Avatar = req.Avatar
    }

    if err := s.userRepo.Update(ctx, user); err != nil {
        s.logger.Error("Ошибка обновления пользователя", zap.Error(err))
        return nil, fmt.Errorf("ошибка обновления пользователя: %w", err)
    }

    s.logger.Info("Пользователь успешно обновлен", zap.String("user_id", userID.String()))

    response := user.ToResponse()
    return &response, nil
}

// ChangePassword изменяет пароль пользователя
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, req *domain.ChangePasswordRequest) error {
    s.logger.Info("Смена пароля", zap.String("user_id", userID.String()))

    user, err := s.userRepo.GetByID(ctx, userID)
    if err != nil {
        if err == gorm.ErrRecordNotFound {
            return fmt.Errorf("пользователь не найден")
        }
        return fmt.Errorf("ошибка получения пользователя: %w", err)
    }

    // Проверяем текущий пароль
    if !user.HasPassword() {
        return fmt.Errorf("у пользователя не установлен пароль")
    }

    if !user.CheckPassword(req.CurrentPassword) {
        return fmt.Errorf("неверный текущий пароль")
    }

    // Устанавливаем новый пароль
    if err := user.SetPassword(req.NewPassword); err != nil {
        return fmt.Errorf("ошибка установки нового пароля: %w", err)
    }

    if err := s.userRepo.Update(ctx, user); err != nil {
        s.logger.Error("Ошибка обновления пароля", zap.Error(err))
        return fmt.Errorf("ошибка обновления пароля: %w", err)
    }

    // Отзываем все refresh токены пользователя
    if err := s.refreshTokenRepo.RevokeByUserID(ctx, userID); err != nil {
        s.logger.Warn("Ошибка отзыва refresh токенов", zap.Error(err))
    }

    s.logger.Info("Пароль успешно изменен", zap.String("user_id", userID.String()))
    return nil
}

// DeleteUser удаляет пользователя (soft delete)
func (s *UserService) DeleteUser(ctx context.Context, userID uuid.UUID) error {
    s.logger.Info("Удаление пользователя", zap.String("user_id", userID.String()))

    if err := s.userRepo.Delete(ctx, userID); err != nil {
        s.logger.Error("Ошибка удаления пользователя", zap.Error(err))
        return fmt.Errorf("ошибка удаления пользователя: %w", err)
    }

    // Удаляем все refresh токены
    if err := s.refreshTokenRepo.DeleteByUserID(ctx, userID); err != nil {
        s.logger.Warn("Ошибка удаления refresh токенов", zap.Error(err))
    }

    s.logger.Info("Пользователь успешно удален", zap.String("user_id", userID.String()))
    return nil
}

// ListUsers получает список пользователей с пагинацией
func (s *UserService) ListUsers(ctx context.Context, req *domain.ListUsersRequest) (*domain.ListUsersResponse, error) {
    filter := repository.ListUsersFilter{
        Page:         req.Page,
        Limit:        req.Limit,
        Search:       req.Search,
        IsActive:     req.IsActive,
        Provider:     req.Provider,
        SortBy:       req.SortBy,
        SortDesc:     req.SortDesc,
        IncludeOAuth: true,
    }

    users, total, err := s.userRepo.List(ctx, filter)
    if err != nil {
        return nil, fmt.Errorf("ошибка получения списка пользователей: %w", err)
    }

    totalPages := int(math.Ceil(float64(total) / float64(req.Limit)))

    userResponses := make([]domain.UserResponse, len(users))
    for i, user := range users {
        userResponses[i] = user.ToResponse()
    }

    return &domain.ListUsersResponse{
        Users:      userResponses,
        Total:      total,
        Page:       req.Page,
        Limit:      req.Limit,
        TotalPages: totalPages,
    }, nil
}

// Login выполняет аутентификацию пользователя по email/паролю
func (s *UserService) Login(ctx context.Context, req *domain.LoginRequest) (*domain.TokenResponse, error) {
    s.logger.Info("Попытка входа", zap.String("email", req.Email))

    user, err := s.userRepo.GetByEmail(ctx, strings.ToLower(req.Email))
    if err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("неверный email или пароль")
        }
        return nil, fmt.Errorf("ошибка получения пользователя: %w", err)
    }

    if !user.IsActive {
        return nil, fmt.Errorf("аккаунт деактивирован")
    }

    if !user.HasPassword() {
        return nil, fmt.Errorf("для этого аккаунта доступна только OAuth авторизация")
    }

    if !user.CheckPassword(req.Password) {
        return nil, fmt.Errorf("неверный email или пароль")
    }

    // Генерируем токены
    tokenPair, err := s.jwtService.GenerateTokenPair(user)
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации токенов: %w", err)
    }

    // Сохраняем refresh токен в БД
    refreshToken := &domain.RefreshToken{
        UserID:    user.ID,
        Token:     tokenPair.RefreshToken,
        ExpiresAt: time.Now().Add(24 * 7 * time.Hour), // 7 дней
    }

    if err := s.refreshTokenRepo.Create(ctx, refreshToken); err != nil {
        s.logger.Error("Ошибка сохранения refresh токена", zap.Error(err))
        return nil, fmt.Errorf("ошибка сохранения refresh токена: %w", err)
    }

    // Обновляем время последнего входа
    if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
        s.logger.Warn("Ошибка обновления времени входа", zap.Error(err))
    }

    s.logger.Info("Успешный вход", zap.String("user_id", user.ID.String()))

    return &domain.TokenResponse{
        AccessToken:  tokenPair.AccessToken,
        RefreshToken: tokenPair.RefreshToken,
        TokenType:    tokenPair.TokenType,
        ExpiresIn:    tokenPair.ExpiresIn,
        ExpiresAt:    tokenPair.ExpiresAt,
    }, nil
}

// RefreshToken обновляет access токен используя refresh токен
func (s *UserService) RefreshToken(ctx context.Context, req *domain.RefreshTokenRequest) (*domain.TokenResponse, error) {
    s.logger.Info("Обновление токена")

    refreshToken, err := s.refreshTokenRepo.GetByToken(ctx, req.RefreshToken)
    if err != nil {
        if err == gorm.ErrRecordNotFound {
            return nil, fmt.Errorf("недействительный refresh токен")
        }
        return nil, fmt.Errorf("ошибка получения refresh токена: %w", err)
    }

    if !refreshToken.IsValid() {
        return nil, fmt.Errorf("refresh токен недействителен или истек")
    }

    if !refreshToken.User.IsActive {
        return nil, fmt.Errorf("аккаунт пользователя деактивирован")
    }

    // Генерируем новую пару токенов
    tokenPair, err := s.jwtService.GenerateTokenPair(&refreshToken.User)
    if err != nil {
        return nil, fmt.Errorf("ошибка генерации токенов: %w", err)
    }

    // Обновляем refresh токен в БД
    refreshToken.Token = tokenPair.RefreshToken
    refreshToken.ExpiresAt = time.Now().Add(24 * 7 * time.Hour)

    if err := s.refreshTokenRepo.Update(ctx, refreshToken); err != nil {
        s.logger.Error("Ошибка обновления refresh токена", zap.Error(err))
        return nil, fmt.Errorf("ошибка обновления refresh токена: %w", err)
    }

    s.logger.Info("Токен успешно обновлен", zap.String("user_id", refreshToken.UserID.String()))

    return &domain.TokenResponse{
        AccessToken:  tokenPair.AccessToken,
        RefreshToken: tokenPair.RefreshToken,
        TokenType:    tokenPair.TokenType,
        ExpiresIn:    tokenPair.ExpiresIn,
        ExpiresAt:    tokenPair.ExpiresAt,
    }, nil
}

// Logout выполняет выход пользователя (отзывает refresh токен)
func (s *UserService) Logout(ctx context.Context, userID uuid.UUID, refreshToken string) error {
    s.logger.Info("Выход пользователя", zap.String("user_id", userID.String()))

    // Отзываем конкретный refresh токен
    token, err := s.refreshTokenRepo.GetByToken(ctx, refreshToken)
    if err == nil {
        token.IsRevoked = true
        if updateErr := s.refreshTokenRepo.Update(ctx, token); updateErr != nil {
            s.logger.Warn("Ошибка отзыва refresh токена", zap.Error(updateErr))
        }
    }

    s.logger.Info("Пользователь успешно вышел", zap.String("user_id", userID.String()))
    return nil
}

// LogoutAll выполняет выход со всех устройств (отзывает все refresh токены)
func (s *UserService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
    s.logger.Info("Выход со всех устройств", zap.String("user_id", userID.String()))

    if err := s.refreshTokenRepo.RevokeByUserID(ctx, userID); err != nil {
        s.logger.Error("Ошибка отзыва всех refresh токенов", zap.Error(err))
        return fmt.Errorf("ошибка выхода со всех устройств: %w", err)
    }

    s.logger.Info("Выход со всех устройств выполнен", zap.String("user_id", userID.String()))
    return nil
}

// CleanupExpiredTokens очищает истекшие refresh токены
func (s *UserService) CleanupExpiredTokens(ctx context.Context) error {
    s.logger.Info("Очистка истекших токенов")

    if err := s.refreshTokenRepo.DeleteExpired(ctx); err != nil {
        s.logger.Error("Ошибка очистки истекших токенов", zap.Error(err))
        return err
    }

    s.logger.Info("Очистка истекших токенов завершена")
    return nil
}
