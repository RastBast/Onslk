package postgres

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/google/uuid"
    "github.com/user-service/internal/domain"
    "github.com/user-service/internal/repository"
    "gorm.io/gorm"
    "gorm.io/gorm/clause"
)

// UserRepository реализация UserRepository для PostgreSQL
type UserRepository struct {
    db *gorm.DB
}

// NewUserRepository создает новый UserRepository
func NewUserRepository(db *gorm.DB) *UserRepository {
    return &UserRepository{db: db}
}

// Create создает нового пользователя
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
    return r.db.WithContext(ctx).Create(user).Error
}

// GetByID получает пользователя по ID
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
    var user domain.User
    err := r.db.WithContext(ctx).
        Preload("OAuthAccounts").
        First(&user, "id = ?", id).Error

    if err != nil {
        return nil, err
    }
    return &user, nil
}

// GetByEmail получает пользователя по email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
    var user domain.User
    err := r.db.WithContext(ctx).
        Preload("OAuthAccounts").
        First(&user, "email = ?", email).Error

    if err != nil {
        return nil, err
    }
    return &user, nil
}

// GetByUsername получает пользователя по username
func (r *UserRepository) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
    var user domain.User
    err := r.db.WithContext(ctx).
        Preload("OAuthAccounts").
        First(&user, "username = ?", username).Error

    if err != nil {
        return nil, err
    }
    return &user, nil
}

// Update обновляет данные пользователя
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
    return r.db.WithContext(ctx).Save(user).Error
}

// Delete удаляет пользователя (soft delete)
func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
    return r.db.WithContext(ctx).Delete(&domain.User{}, "id = ?", id).Error
}

// List получает список пользователей с пагинацией и фильтрацией
func (r *UserRepository) List(ctx context.Context, filter repository.ListUsersFilter) ([]domain.User, int64, error) {
    var users []domain.User
    var total int64

    query := r.db.WithContext(ctx).Model(&domain.User{})

    // Применяем фильтры
    if filter.Search != "" {
        searchTerm := "%" + strings.ToLower(filter.Search) + "%"
        query = query.Where(
            "LOWER(first_name) LIKE ? OR LOWER(last_name) LIKE ? OR LOWER(username) LIKE ? OR LOWER(email) LIKE ?",
            searchTerm, searchTerm, searchTerm, searchTerm,
        )
    }

    if filter.IsActive != nil {
        query = query.Where("is_active = ?", *filter.IsActive)
    }

    if filter.Provider != "" {
        query = query.Joins("INNER JOIN oauth_accounts ON oauth_accounts.user_id = users.id").
            Where("oauth_accounts.provider = ?", filter.Provider)
    }

    // Подсчет общего количества
    if err := query.Count(&total).Error; err != nil {
        return nil, 0, err
    }

    // Сортировка
    orderBy := "created_at DESC"
    if filter.SortBy != "" {
        direction := "ASC"
        if filter.SortDesc {
            direction = "DESC"
        }
        orderBy = fmt.Sprintf("%s %s", filter.SortBy, direction)
    }

    query = query.Order(orderBy)

    // Пагинация
    offset := (filter.Page - 1) * filter.Limit
    query = query.Offset(offset).Limit(filter.Limit)

    // Загрузка связанных данных
    if filter.IncludeOAuth {
        query = query.Preload("OAuthAccounts")
    }

    if err := query.Find(&users).Error; err != nil {
        return nil, 0, err
    }

    return users, total, nil
}

// UpdateLastLogin обновляет время последнего входа
func (r *UserRepository) UpdateLastLogin(ctx context.Context, userID uuid.UUID) error {
    now := time.Now()
    return r.db.WithContext(ctx).
        Model(&domain.User{}).
        Where("id = ?", userID).
        Update("last_login_at", now).Error
}

// ExistsByEmail проверяет существование пользователя по email
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
    var count int64
    err := r.db.WithContext(ctx).
        Model(&domain.User{}).
        Where("email = ?", email).
        Count(&count).Error

    return count > 0, err
}

// ExistsByUsername проверяет существование пользователя по username
func (r *UserRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
    var count int64
    err := r.db.WithContext(ctx).
        Model(&domain.User{}).
        Where("username = ?", username).
        Count(&count).Error

    return count > 0, err
}

// OAuthRepository реализация OAuthRepository для PostgreSQL
type OAuthRepository struct {
    db *gorm.DB
}

// NewOAuthRepository создает новый OAuthRepository
func NewOAuthRepository(db *gorm.DB) *OAuthRepository {
    return &OAuthRepository{db: db}
}

// Create создает OAuth аккаунт
func (r *OAuthRepository) Create(ctx context.Context, account *domain.OAuthAccount) error {
    return r.db.WithContext(ctx).Create(account).Error
}

// GetByProviderAndUserID получает OAuth аккаунт по провайдеру и ID пользователя
func (r *OAuthRepository) GetByProviderAndUserID(ctx context.Context, provider string, userID uuid.UUID) (*domain.OAuthAccount, error) {
    var account domain.OAuthAccount
    err := r.db.WithContext(ctx).
        Where("provider = ? AND user_id = ?", provider, userID).
        First(&account).Error

    if err != nil {
        return nil, err
    }
    return &account, nil
}

// GetByProviderAndProviderID получает OAuth аккаунт по провайдеру и внешнему ID
func (r *OAuthRepository) GetByProviderAndProviderID(ctx context.Context, provider, providerID string) (*domain.OAuthAccount, error) {
    var account domain.OAuthAccount
    err := r.db.WithContext(ctx).
        Preload("User").
        Where("provider = ? AND provider_id = ?", provider, providerID).
        First(&account).Error

    if err != nil {
        return nil, err
    }
    return &account, nil
}

// Update обновляет OAuth аккаунт
func (r *OAuthRepository) Update(ctx context.Context, account *domain.OAuthAccount) error {
    return r.db.WithContext(ctx).Save(account).Error
}

// Delete удаляет OAuth аккаунт
func (r *OAuthRepository) Delete(ctx context.Context, id uuid.UUID) error {
    return r.db.WithContext(ctx).Delete(&domain.OAuthAccount{}, "id = ?", id).Error
}

// ListByUserID получает все OAuth аккаунты пользователя
func (r *OAuthRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]domain.OAuthAccount, error) {
    var accounts []domain.OAuthAccount
    err := r.db.WithContext(ctx).
        Where("user_id = ?", userID).
        Find(&accounts).Error

    return accounts, err
}

// RefreshTokenRepository реализация RefreshTokenRepository для PostgreSQL
type RefreshTokenRepository struct {
    db *gorm.DB
}

// NewRefreshTokenRepository создает новый RefreshTokenRepository
func NewRefreshTokenRepository(db *gorm.DB) *RefreshTokenRepository {
    return &RefreshTokenRepository{db: db}
}

// Create создает refresh токен
func (r *RefreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
    return r.db.WithContext(ctx).Create(token).Error
}

// GetByToken получает refresh токен по значению
func (r *RefreshTokenRepository) GetByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
    var refreshToken domain.RefreshToken
    err := r.db.WithContext(ctx).
        Preload("User").
        Where("token = ? AND is_revoked = false", token).
        First(&refreshToken).Error

    if err != nil {
        return nil, err
    }
    return &refreshToken, nil
}

// Update обновляет refresh токен
func (r *RefreshTokenRepository) Update(ctx context.Context, token *domain.RefreshToken) error {
    return r.db.WithContext(ctx).Save(token).Error
}

// Delete удаляет refresh токен
func (r *RefreshTokenRepository) Delete(ctx context.Context, id uuid.UUID) error {
    return r.db.WithContext(ctx).Delete(&domain.RefreshToken{}, "id = ?", id).Error
}

// DeleteByUserID удаляет все refresh токены пользователя
func (r *RefreshTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
    return r.db.WithContext(ctx).
        Where("user_id = ?", userID).
        Delete(&domain.RefreshToken{}).Error
}

// DeleteExpired удаляет все истекшие токены
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
    return r.db.WithContext(ctx).
        Where("expires_at < ?", time.Now()).
        Delete(&domain.RefreshToken{}).Error
}

// RevokeByUserID отзывает все токены пользователя
func (r *RefreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
    return r.db.WithContext(ctx).
        Model(&domain.RefreshToken{}).
        Where("user_id = ? AND is_revoked = false", userID).
        Update("is_revoked", true).Error
}
