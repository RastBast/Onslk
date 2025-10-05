package domain

import (
    "time"
    "github.com/google/uuid"
)

// CreateUserRequest представляет запрос на создание пользователя
type CreateUserRequest struct {
    Email     string `json:"email" validate:"required,email"`
    Username  string `json:"username" validate:"required,min=3,max=50"`
    FirstName string `json:"first_name" validate:"required,min=1,max=100"`
    LastName  string `json:"last_name" validate:"required,min=1,max=100"`
    Password  string `json:"password" validate:"required,min=8,max=128"`
}

// UpdateUserRequest представляет запрос на обновление пользователя
type UpdateUserRequest struct {
    FirstName *string `json:"first_name,omitempty" validate:"omitempty,min=1,max=100"`
    LastName  *string `json:"last_name,omitempty" validate:"omitempty,min=1,max=100"`
    Avatar    *string `json:"avatar,omitempty"`
}

// ChangePasswordRequest представляет запрос на смену пароля
type ChangePasswordRequest struct {
    CurrentPassword string `json:"current_password" validate:"required"`
    NewPassword     string `json:"new_password" validate:"required,min=8,max=128"`
}

// LoginRequest представляет запрос на аутентификацию
type LoginRequest struct {
    Email    string `json:"email" validate:"required,email"`
    Password string `json:"password" validate:"required"`
}

// TokenResponse представляет ответ с токенами
type TokenResponse struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresIn    int64     `json:"expires_in"`
    ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshTokenRequest представляет запрос на обновление токена
type RefreshTokenRequest struct {
    RefreshToken string `json:"refresh_token" validate:"required"`
}

// UserResponse представляет ответ с данными пользователя
type UserResponse struct {
    ID           uuid.UUID    `json:"id"`
    Email        string       `json:"email"`
    Username     string       `json:"username"`
    FirstName    string       `json:"first_name"`
    LastName     string       `json:"last_name"`
    Avatar       *string      `json:"avatar"`
    IsActive     bool         `json:"is_active"`
    IsVerified   bool         `json:"is_verified"`
    LastLoginAt  *time.Time   `json:"last_login_at"`
    CreatedAt    time.Time    `json:"created_at"`
    UpdatedAt    time.Time    `json:"updated_at"`
    OAuthAccounts []OAuthAccountResponse `json:"oauth_accounts,omitempty"`
}

// OAuthAccountResponse представляет ответ с OAuth аккаунтом
type OAuthAccountResponse struct {
    ID         uuid.UUID  `json:"id"`
    Provider   string     `json:"provider"`
    Email      string     `json:"email,omitempty"`
    Username   string     `json:"username,omitempty"`
    Avatar     string     `json:"avatar,omitempty"`
    ExpiresAt  *time.Time `json:"expires_at,omitempty"`
    CreatedAt  time.Time  `json:"created_at"`
}

// OAuthLoginRequest представляет запрос OAuth авторизации
type OAuthLoginRequest struct {
    Provider string `json:"provider" validate:"required,oneof=google github telegram"`
    Code     string `json:"code,omitempty"`
    State    string `json:"state,omitempty"`
}

// TelegramAuthData представляет данные авторизации Telegram
type TelegramAuthData struct {
    ID        int64  `json:"id" validate:"required"`
    FirstName string `json:"first_name" validate:"required"`
    LastName  string `json:"last_name,omitempty"`
    Username  string `json:"username,omitempty"`
    PhotoURL  string `json:"photo_url,omitempty"`
    AuthDate  int64  `json:"auth_date" validate:"required"`
    Hash      string `json:"hash" validate:"required"`
}

// ErrorResponse представляет ответ с ошибкой
type ErrorResponse struct {
    Code    int    `json:"code"`
    Message string `json:"message"`
    Details string `json:"details,omitempty"`
}

// ListUsersRequest представляет запрос на получение списка пользователей
type ListUsersRequest struct {
    Page     int    `form:"page,default=1" validate:"min=1"`
    Limit    int    `form:"limit,default=20" validate:"min=1,max=100"`
    Search   string `form:"search"`
    IsActive *bool  `form:"is_active"`
    Provider string `form:"provider"`
    SortBy   string `form:"sort_by,default=created_at" validate:"oneof=created_at updated_at username email"`
    SortDesc bool   `form:"sort_desc,default=false"`
}

// ListUsersResponse представляет ответ со списком пользователей
type ListUsersResponse struct {
    Users      []UserResponse `json:"users"`
    Total      int64          `json:"total"`
    Page       int            `json:"page"`
    Limit      int            `json:"limit"`
    TotalPages int            `json:"total_pages"`
}

// ToUserResponse converts User to UserResponse
func (u *User) ToResponse() UserResponse {
    response := UserResponse{
        ID:          u.ID,
        Email:       u.Email,
        Username:    u.Username,
        FirstName:   u.FirstName,
        LastName:    u.LastName,
        Avatar:      u.Avatar,
        IsActive:    u.IsActive,
        IsVerified:  u.IsVerified,
        LastLoginAt: u.LastLoginAt,
        CreatedAt:   u.CreatedAt,
        UpdatedAt:   u.UpdatedAt,
    }

    if len(u.OAuthAccounts) > 0 {
        response.OAuthAccounts = make([]OAuthAccountResponse, len(u.OAuthAccounts))
        for i, oauth := range u.OAuthAccounts {
            response.OAuthAccounts[i] = OAuthAccountResponse{
                ID:        oauth.ID,
                Provider:  oauth.Provider,
                Email:     oauth.Email,
                Username:  oauth.Username,
                Avatar:    oauth.Avatar,
                ExpiresAt: oauth.ExpiresAt,
                CreatedAt: oauth.CreatedAt,
            }
        }
    }

    return response
}
