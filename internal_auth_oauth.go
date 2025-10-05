package auth

import (
    "encoding/json"
    "net/http"
    "github.com/google/uuid"

    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strconv"
    "time"

    "github.com/user-service/internal/config"
    "github.com/user-service/internal/domain"
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/github"
    "golang.org/x/oauth2/google"
)

// OAuthService предоставляет функциональность для OAuth2 авторизации
type OAuthService struct {
    config        *config.OAuthConfig
    googleConfig  *oauth2.Config
    githubConfig  *oauth2.Config
}

// NewOAuthService создает новый OAuthService
func NewOAuthService(cfg *config.OAuthConfig) *OAuthService {
    service := &OAuthService{
        config: cfg,
    }

    // Настройка Google OAuth
    if cfg.Google.ClientID != "" {
        service.googleConfig = &oauth2.Config{
            ClientID:     cfg.Google.ClientID,
            ClientSecret: cfg.Google.ClientSecret,
            RedirectURL:  cfg.Google.RedirectURL,
            Scopes:       cfg.Google.Scopes,
            Endpoint:     google.Endpoint,
        }
    }

    // Настройка GitHub OAuth
    if cfg.GitHub.ClientID != "" {
        service.githubConfig = &oauth2.Config{
            ClientID:     cfg.GitHub.ClientID,
            ClientSecret: cfg.GitHub.ClientSecret,
            RedirectURL:  cfg.GitHub.RedirectURL,
            Scopes:       cfg.GitHub.Scopes,
            Endpoint:     github.Endpoint,
        }
    }

    return service
}

// GoogleUserInfo представляет информацию о пользователе Google
type GoogleUserInfo struct {
    ID            string `json:"id"`
    Email         string `json:"email"`
    VerifiedEmail bool   `json:"verified_email"`
    Name          string `json:"name"`
    GivenName     string `json:"given_name"`
    FamilyName    string `json:"family_name"`
    Picture       string `json:"picture"`
    Locale        string `json:"locale"`
}

// GitHubUserInfo представляет информацию о пользователе GitHub
type GitHubUserInfo struct {
    ID        int64  `json:"id"`
    Login     string `json:"login"`
    Name      string `json:"name"`
    Email     string `json:"email"`
    AvatarURL string `json:"avatar_url"`
    Company   string `json:"company"`
    Location  string `json:"location"`
}

// GitHubEmail представляет email адрес пользователя GitHub
type GitHubEmail struct {
    Email    string `json:"email"`
    Primary  bool   `json:"primary"`
    Verified bool   `json:"verified"`
}

// GetAuthURL возвращает URL для авторизации через указанного провайдера
func (s *OAuthService) GetAuthURL(provider, state string) (string, error) {
    switch provider {
    case domain.ProviderGoogle:
        if s.googleConfig == nil {
            return "", fmt.Errorf("Google OAuth не настроен")
        }
        return s.googleConfig.AuthCodeURL(state, oauth2.AccessTypeOffline), nil

    case domain.ProviderGitHub:
        if s.githubConfig == nil {
            return "", fmt.Errorf("GitHub OAuth не настроен")
        }
        return s.githubConfig.AuthCodeURL(state), nil

    default:
        return "", fmt.Errorf("неподдерживаемый провайдер: %s", provider)
    }
}

// ExchangeCodeForToken обменивает authorization code на токен
func (s *OAuthService) ExchangeCodeForToken(ctx context.Context, provider, code string) (*oauth2.Token, error) {
    switch provider {
    case domain.ProviderGoogle:
        if s.googleConfig == nil {
            return nil, fmt.Errorf("Google OAuth не настроен")
        }
        return s.googleConfig.Exchange(ctx, code)

    case domain.ProviderGitHub:
        if s.githubConfig == nil {
            return nil, fmt.Errorf("GitHub OAuth не настроен")
        }
        return s.githubConfig.Exchange(ctx, code)

    default:
        return nil, fmt.Errorf("неподдерживаемый провайдер: %s", provider)
    }
}

// GetUserInfo получает информацию о пользователе от OAuth провайдера
func (s *OAuthService) GetUserInfo(ctx context.Context, provider string, token *oauth2.Token) (interface{}, error) {
    switch provider {
    case domain.ProviderGoogle:
        return s.getGoogleUserInfo(ctx, token)

    case domain.ProviderGitHub:
        return s.getGitHubUserInfo(ctx, token)

    default:
        return nil, fmt.Errorf("неподдерживаемый провайдер: %s", provider)
    }
}

// ValidateTelegramAuth валидирует данные авторизации Telegram
func (s *OAuthService) ValidateTelegramAuth(data *domain.TelegramAuthData) error {
    if s.config.Telegram.BotToken == "" {
        return fmt.Errorf("Telegram авторизация не настроена")
    }

    // Проверяем время авторизации (не старше 1 часа)
    authTime := time.Unix(data.AuthDate, 0)
    if time.Since(authTime) > time.Hour {
        return fmt.Errorf("данные авторизации устарели")
    }

    // Создаем строку для проверки подписи
    dataString := fmt.Sprintf("auth_date=%d\nfirst_name=%s\nid=%d",
        data.AuthDate, data.FirstName, data.ID)

    if data.LastName != "" {
        dataString += fmt.Sprintf("\nlast_name=%s", data.LastName)
    }

    if data.PhotoURL != "" {
        dataString += fmt.Sprintf("\nphoto_url=%s", data.PhotoURL)
    }

    if data.Username != "" {
        dataString += fmt.Sprintf("\nusername=%s", data.Username)
    }

    // Вычисляем секретный ключ
    secretKey := sha256.Sum256([]byte(s.config.Telegram.BotToken))

    // Вычисляем HMAC
    mac := hmac.New(sha256.New, secretKey[:])
    mac.Write([]byte(dataString))
    expectedHash := hex.EncodeToString(mac.Sum(nil))

    // Сравниваем с переданным хэшем
    if expectedHash != data.Hash {
        return fmt.Errorf("неверная подпись данных авторизации")
    }

    return nil
}

// CreateOAuthAccount создает domain.OAuthAccount из данных провайдера
func (s *OAuthService) CreateOAuthAccount(userID uuid.UUID, provider string, userData interface{}, token *oauth2.Token) (*domain.OAuthAccount, error) {
    account := &domain.OAuthAccount{
        UserID:   userID,
        Provider: provider,
    }

    if token != nil {
        account.AccessToken = token.AccessToken
        if token.RefreshToken != "" {
            account.RefreshToken = &token.RefreshToken
        }
        if !token.Expiry.IsZero() {
            account.ExpiresAt = &token.Expiry
        }
    }

    switch provider {
    case domain.ProviderGoogle:
        googleUser, ok := userData.(*GoogleUserInfo)
        if !ok {
            return nil, fmt.Errorf("неверный тип данных для Google")
        }
        account.ProviderID = googleUser.ID
        account.Email = googleUser.Email
        account.Username = googleUser.Name
        account.Avatar = googleUser.Picture

    case domain.ProviderGitHub:
        githubUser, ok := userData.(*GitHubUserInfo)
        if !ok {
            return nil, fmt.Errorf("неверный тип данных для GitHub")
        }
        account.ProviderID = strconv.FormatInt(githubUser.ID, 10)
        account.Email = githubUser.Email
        account.Username = githubUser.Login
        account.Avatar = githubUser.AvatarURL

    case domain.ProviderTelegram:
        telegramData, ok := userData.(*domain.TelegramAuthData)
        if !ok {
            return nil, fmt.Errorf("неверный тип данных для Telegram")
        }
        account.ProviderID = strconv.FormatInt(telegramData.ID, 10)
        account.Username = telegramData.Username
        if telegramData.PhotoURL != "" {
            account.Avatar = telegramData.PhotoURL
        }

    default:
        return nil, fmt.Errorf("неподдерживаемый провайдер: %s", provider)
    }

    return account, nil
}

// Внутренние методы для получения информации о пользователях
func (s *OAuthService) getGoogleUserInfo(ctx context.Context, token *oauth2.Token) (*GoogleUserInfo, error) {
    client := s.googleConfig.Client(ctx, token)

    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
    if err != nil {
        return nil, fmt.Errorf("ошибка получения информации о пользователе Google: %w", err)
    }
    defer resp.Body.Close()

    var userInfo GoogleUserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, fmt.Errorf("ошибка декодирования ответа Google: %w", err)
    }

    return &userInfo, nil
}

func (s *OAuthService) getGitHubUserInfo(ctx context.Context, token *oauth2.Token) (*GitHubUserInfo, error) {
    client := s.githubConfig.Client(ctx, token)

    // Получаем основную информацию о пользователе
    resp, err := client.Get("https://api.github.com/user")
    if err != nil {
        return nil, fmt.Errorf("ошибка получения информации о пользователе GitHub: %w", err)
    }
    defer resp.Body.Close()

    var userInfo GitHubUserInfo
    if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
        return nil, fmt.Errorf("ошибка декодирования ответа GitHub: %w", err)
    }

    // Если email не публичный, получаем его отдельно
    if userInfo.Email == "" {
        email, err := s.getGitHubUserEmail(ctx, client)
        if err == nil {
            userInfo.Email = email
        }
    }

    return &userInfo, nil
}

func (s *OAuthService) getGitHubUserEmail(ctx context.Context, client *http.Client) (string, error) {
    resp, err := client.Get("https://api.github.com/user/emails")
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    var emails []GitHubEmail
    if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
        return "", err
    }

    // Ищем основной проверенный email
    for _, email := range emails {
        if email.Primary && email.Verified {
            return email.Email, nil
        }
    }

    // Если основного нет, берем первый проверенный
    for _, email := range emails {
        if email.Verified {
            return email.Email, nil
        }
    }

    return "", fmt.Errorf("проверенный email не найден")
}
