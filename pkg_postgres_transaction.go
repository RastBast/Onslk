package postgres

import (
    "context"
    "fmt"

    "github.com/user-service/internal/repository"
    "gorm.io/gorm"
)

// TransactionManager реализация TransactionManager для PostgreSQL
type TransactionManager struct {
    db *gorm.DB
}

// NewTransactionManager создает новый TransactionManager
func NewTransactionManager(db *gorm.DB) *TransactionManager {
    return &TransactionManager{db: db}
}

// WithTransaction выполняет функцию в рамках транзакции
func (tm *TransactionManager) WithTransaction(ctx context.Context, fn func(ctx context.Context, tx repository.Transaction) error) error {
    return tm.db.WithContext(ctx).Transaction(func(gormTx *gorm.DB) error {
        tx := &Transaction{db: gormTx}
        return fn(ctx, tx)
    })
}

// Transaction реализация Transaction для PostgreSQL
type Transaction struct {
    db *gorm.DB
}

// Commit фиксирует транзакцию (в GORM это происходит автоматически)
func (t *Transaction) Commit() error {
    // В GORM транзакция фиксируется автоматически при успешном завершении
    return nil
}

// Rollback откатывает транзакцию (в GORM это происходит автоматически при ошибке)
func (t *Transaction) Rollback() error {
    // В GORM транзакция откатывается автоматически при возврате ошибки
    return nil
}

// GetUserRepository возвращает user repository в рамках транзакции
func (t *Transaction) GetUserRepository() repository.UserRepository {
    return NewUserRepository(t.db)
}

// GetOAuthRepository возвращает oauth repository в рамках транзакции
func (t *Transaction) GetOAuthRepository() repository.OAuthRepository {
    return NewOAuthRepository(t.db)
}

// GetRefreshTokenRepository возвращает refresh token repository в рамках транзакции
func (t *Transaction) GetRefreshTokenRepository() repository.RefreshTokenRepository {
    return NewRefreshTokenRepository(t.db)
}
