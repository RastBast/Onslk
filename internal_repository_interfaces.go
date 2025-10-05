package repository

import (
    "context"
    "github.com/google/uuid"
    "github.com/user-service/internal/domain"
)

// UserRepository определяет интерфейс для работы с пользователями
type UserRepository interface {
    // Create создает нового пользователя
    Create(ctx context.Context, user *domain.User) error

    // GetByID получает пользователя по ID
    GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)

    // GetByEmail получает пользователя по email
    GetByEmail(ctx context.Context, email string) (*domain.User, error)

    // GetByUsername получает пользователя по username
    GetByUsername(ctx context.Context, username string) (*domain.User, error)

    // Update обновляет данные пользователя
    Update(ctx context.Context, user *domain.User) error

    // Delete удаляет пользователя (soft delete)
    Delete(ctx context.Context, id uuid.UUID) error

    // List получает список пользователей с пагинацией и фильтрацией
    List(ctx context.Context, filter ListUsersFilter) ([]domain.User, int64, error)

    // UpdateLastLogin обновляет время последнего входа
    UpdateLastLogin(ctx context.Context, userID uuid.UUID) error

    // ExistsByEmail проверяет существование пользователя по email
    ExistsByEmail(ctx context.Context, email string) (bool, error)

    // ExistsByUsername проверяет существование пользователя по username
    ExistsByUsername(ctx context.Context, username string) (bool, error)
}

// OAuthRepository определяет интерфейс для работы с OAuth аккаунтами
type OAuthRepository interface {
    // Create создает OAuth аккаунт
    Create(ctx context.Context, account *domain.OAuthAccount) error

    // GetByProviderAndUserID получает OAuth аккаунт по провайдеру и ID пользователя
    GetByProviderAndUserID(ctx context.Context, provider string, userID uuid.UUID) (*domain.OAuthAccount, error)

    // GetByProviderAndProviderID получает OAuth аккаунт по провайдеру и внешнему ID
    GetByProviderAndProviderID(ctx context.Context, provider, providerID string) (*domain.OAuthAccount, error)

    // Update обновляет OAuth аккаунт
    Update(ctx context.Context, account *domain.OAuthAccount) error

    // Delete удаляет OAuth аккаунт
    Delete(ctx context.Context, id uuid.UUID) error

    // ListByUserID получает все OAuth аккаунты пользователя
    ListByUserID(ctx context.Context, userID uuid.UUID) ([]domain.OAuthAccount, error)
}

// RefreshTokenRepository определяет интерфейс для работы с refresh токенами
type RefreshTokenRepository interface {
    // Create создает refresh токен
    Create(ctx context.Context, token *domain.RefreshToken) error

    // GetByToken получает refresh токен по значению
    GetByToken(ctx context.Context, token string) (*domain.RefreshToken, error)

    // Update обновляет refresh токен
    Update(ctx context.Context, token *domain.RefreshToken) error

    // Delete удаляет refresh токен
    Delete(ctx context.Context, id uuid.UUID) error

    // DeleteByUserID удаляет все refresh токены пользователя
    DeleteByUserID(ctx context.Context, userID uuid.UUID) error

    // DeleteExpired удаляет все истекшие токены
    DeleteExpired(ctx context.Context) error

    // RevokeByUserID отзывает все токены пользователя
    RevokeByUserID(ctx context.Context, userID uuid.UUID) error
}

// Repositories объединяет все репозитории
type Repositories struct {
    User         UserRepository
    OAuth        OAuthRepository
    RefreshToken RefreshTokenRepository
}

// ListUsersFilter содержит параметры фильтрации пользователей
type ListUsersFilter struct {
    Page       int
    Limit      int
    Search     string
    IsActive   *bool
    Provider   string
    SortBy     string
    SortDesc   bool
    IncludeOAuth bool
}

// Transaction определяет интерфейс для работы с транзакциями
type Transaction interface {
    // Commit фиксирует транзакцию
    Commit() error

    // Rollback откатывает транзакцию
    Rollback() error

    // GetUserRepository возвращает user repository в рамках транзакции
    GetUserRepository() UserRepository

    // GetOAuthRepository возвращает oauth repository в рамках транзакции
    GetOAuthRepository() OAuthRepository

    // GetRefreshTokenRepository возвращает refresh token repository в рамках транзакции
    GetRefreshTokenRepository() RefreshTokenRepository
}

// TransactionManager определяет интерфейс для управления транзакциями
type TransactionManager interface {
    // WithTransaction выполняет функцию в рамках транзакции
    WithTransaction(ctx context.Context, fn func(ctx context.Context, tx Transaction) error) error
}
