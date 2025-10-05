package domain

import (
    "time"
    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"
)

// User представляет модель пользователя
type User struct {
    ID           uuid.UUID      `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    Email        string         `json:"email" gorm:"uniqueIndex;not null" validate:"required,email"`
    Username     string         `json:"username" gorm:"uniqueIndex;not null" validate:"required,min=3,max=50"`
    FirstName    string         `json:"first_name" gorm:"not null" validate:"required,min=1,max=100"`
    LastName     string         `json:"last_name" gorm:"not null" validate:"required,min=1,max=100"`
    PasswordHash *string        `json:"-" gorm:"column:password_hash"`
    Avatar       *string        `json:"avatar"`
    IsActive     bool           `json:"is_active" gorm:"default:true"`
    IsVerified   bool           `json:"is_verified" gorm:"default:false"`
    LastLoginAt  *time.Time     `json:"last_login_at"`
    CreatedAt    time.Time      `json:"created_at" gorm:"autoCreateTime"`
    UpdatedAt    time.Time      `json:"updated_at" gorm:"autoUpdateTime"`
    DeletedAt    gorm.DeletedAt `json:"-" gorm:"index"`

    // OAuth связи
    OAuthAccounts []OAuthAccount `json:"oauth_accounts,omitempty" gorm:"foreignKey:UserID"`

    // Refresh tokens
    RefreshTokens []RefreshToken `json:"-" gorm:"foreignKey:UserID"`
}

// OAuthAccount представляет OAuth аккаунт пользователя
type OAuthAccount struct {
    ID           uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    UserID       uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
    Provider     string    `json:"provider" gorm:"not null;index"` // google, github, telegram
    ProviderID   string    `json:"provider_id" gorm:"not null"`
    Email        string    `json:"email"`
    Username     string    `json:"username"`
    Avatar       string    `json:"avatar"`
    AccessToken  string    `json:"-"`
    RefreshToken *string   `json:"-"`
    ExpiresAt    *time.Time `json:"expires_at"`
    CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"`
    UpdatedAt    time.Time `json:"updated_at" gorm:"autoUpdateTime"`

    User User `json:"-" gorm:"constraint:OnDelete:CASCADE"`
}

// RefreshToken представляет refresh токен
type RefreshToken struct {
    ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
    UserID    uuid.UUID `json:"user_id" gorm:"type:uuid;not null;index"`
    Token     string    `json:"-" gorm:"not null;uniqueIndex"`
    ExpiresAt time.Time `json:"expires_at" gorm:"not null"`
    IsRevoked bool      `json:"is_revoked" gorm:"default:false"`
    CreatedAt time.Time `json:"created_at" gorm:"autoCreateTime"`

    User User `json:"-" gorm:"constraint:OnDelete:CASCADE"`
}

// UserRole представляет роль пользователя
type UserRole struct {
    ID   uint   `json:"id" gorm:"primary_key"`
    Name string `json:"name" gorm:"uniqueIndex;not null"`
}

// UserRoleAssignment представляет связь пользователя с ролью
type UserRoleAssignment struct {
    UserID   uuid.UUID `json:"user_id" gorm:"type:uuid;not null;primaryKey"`
    RoleID   uint      `json:"role_id" gorm:"not null;primaryKey"`

    User User     `json:"-" gorm:"constraint:OnDelete:CASCADE"`
    Role UserRole `json:"-" gorm:"constraint:OnDelete:CASCADE"`
}

// SetPassword устанавливает пароль пользователя с хэшированием
func (u *User) SetPassword(password string) error {
    if password == "" {
        u.PasswordHash = nil
        return nil
    }

    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    hashStr := string(hash)
    u.PasswordHash = &hashStr
    return nil
}

// CheckPassword проверяет пароль пользователя
func (u *User) CheckPassword(password string) bool {
    if u.PasswordHash == nil {
        return false
    }
    return bcrypt.CompareHashAndPassword([]byte(*u.PasswordHash), []byte(password)) == nil
}

// HasPassword проверяет, установлен ли пароль у пользователя
func (u *User) HasPassword() bool {
    return u.PasswordHash != nil
}

// GetFullName возвращает полное имя пользователя
func (u *User) GetFullName() string {
    return u.FirstName + " " + u.LastName
}

// IsExpired проверяет, истек ли refresh token
func (rt *RefreshToken) IsExpired() bool {
    return time.Now().After(rt.ExpiresAt)
}

// IsValid проверяет, действителен ли refresh token
func (rt *RefreshToken) IsValid() bool {
    return !rt.IsRevoked && !rt.IsExpired()
}

// TableName устанавливает имя таблицы для OAuthAccount
func (OAuthAccount) TableName() string {
    return "oauth_accounts"
}

// TableName устанавливает имя таблицы для RefreshToken
func (RefreshToken) TableName() string {
    return "refresh_tokens"
}

// TableName устанавливает имя таблицы для UserRole
func (UserRole) TableName() string {
    return "user_roles"
}

// TableName устанавливает имя таблицы для UserRoleAssignment
func (UserRoleAssignment) TableName() string {
    return "user_role_assignments"
}

// AuthProvider константы для OAuth провайдеров
const (
    ProviderGoogle   = "google"
    ProviderGitHub   = "github"
    ProviderTelegram = "telegram"
)

// UserRole константы
const (
    RoleUser  = "user"
    RoleAdmin = "admin"
)
