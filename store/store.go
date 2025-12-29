package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	db "github.com/kainos-it-com/kainos-auth/db/sqlc"
)

type Store interface {
	db.Querier
	ExecTx(ctx context.Context, fn func(db.Querier) error) error
	Close()

	// User methods
	CreateUserWithID(ctx context.Context, input CreateUserInput) (db.User, error)
	UpdateUserFields(ctx context.Context, input UpdateUserInput) (db.User, error)
	ChangeUserEmail(ctx context.Context, userID, newEmail string, verified bool) (db.User, error)
	DeleteUserWithCleanup(ctx context.Context, userID string) error
	GetUserWithAccounts(ctx context.Context, userID string) (*UserWithAccounts, error)
	GetUserWithSessions(ctx context.Context, userID string) (*UserWithSessions, error)
	ListUsersPaginated(ctx context.Context, page, pageSize int32) (*PaginatedUsers, error)
	IsEmailTaken(ctx context.Context, email string) (bool, error)
	GetUserStats(ctx context.Context, userID string) (*UserStats, error)
	CreateUserWithCredential(ctx context.Context, input CreateUserInput, passwordHash string) (*UserWithAccounts, error)
	CreateUserWithOAuth(ctx context.Context, input CreateUserInput, providerID, accountID string, tokens *OAuthTokens) (*UserWithAccounts, error)

	// Session methods
	CreateSessionForUser(ctx context.Context, input CreateSessionInput) (db.Session, error)
	ValidateSession(ctx context.Context, token string) (*GetSessionWithUserRow, error)
	RefreshSession(ctx context.Context, sessionID string, duration time.Duration) (db.Session, error)
	RevokeAllUserSessions(ctx context.Context, userID string) error
	RevokeOtherUserSessions(ctx context.Context, userID, currentSessionID string) error
	GetActiveSessionCount(ctx context.Context, userID string) (int64, error)
	CleanupExpiredSessions(ctx context.Context) error
	GetFullSession(ctx context.Context, token string) (*SessionWithUser, error)
	IsSessionFresh(ctx context.Context, token string, freshAge time.Duration) (bool, error)
	RevokeSessionByToken(ctx context.Context, token string) error

	// Account methods
	LinkOAuthAccount(ctx context.Context, input LinkAccountInput) (db.Account, error)
	UnlinkOAuthAccount(ctx context.Context, userID, providerID string) error
	GetCredentialAccount(ctx context.Context, userID string) (*db.Account, error)
	HasPassword(ctx context.Context, userID string) (bool, error)
	SetPassword(ctx context.Context, userID, passwordHash string) (db.Account, error)
	ChangePassword(ctx context.Context, userID, newPasswordHash string, revokeOtherSessions bool, currentSessionID string) error
	RefreshOAuthTokens(ctx context.Context, accountID string, tokens *OAuthTokens) (db.Account, error)
	FindAccountByProvider(ctx context.Context, providerID, accountID string) (*db.Account, error)
	GetUserProviders(ctx context.Context, userID string) ([]string, error)
	HasProvider(ctx context.Context, userID, providerID string) (bool, error)

	// Verification methods
	CreateEmailVerification(ctx context.Context, email string, expiresIn *time.Duration) (db.Verification, error)
	CreatePasswordReset(ctx context.Context, email string, expiresIn *time.Duration) (db.Verification, error)
	CreateEmailChange(ctx context.Context, userID, newEmail string, expiresIn *time.Duration) (db.Verification, error)
	CreateDeleteAccountVerification(ctx context.Context, userID string, expiresIn *time.Duration) (db.Verification, error)
	ValidateEmailVerification(ctx context.Context, email, token string) (*db.Verification, error)
	ValidatePasswordReset(ctx context.Context, email, token string) (*db.Verification, error)
	ValidateEmailChange(ctx context.Context, userID, newEmail, token string) (*db.Verification, error)
	ValidateDeleteAccount(ctx context.Context, userID, token string) (*db.Verification, error)
	ConsumeVerification(ctx context.Context, id string) error
	CleanupExpiredVerifications(ctx context.Context) error
	InvalidateUserVerifications(ctx context.Context, identifier string) error
	VerifyEmailWithToken(ctx context.Context, email, token string) error
	ResetPasswordWithToken(ctx context.Context, email, token, newPasswordHash string) error
}

type SQLStore struct {
	pool *pgxpool.Pool
	*db.Queries
}

func NewStore(ctx context.Context, connString string) (Store, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return &SQLStore{
		pool:    pool,
		Queries: db.New(pool),
	}, nil
}

func (s *SQLStore) Close() {
	s.pool.Close()
}

func (s *SQLStore) ExecTx(ctx context.Context, fn func(db.Querier) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	q := db.New(tx)
	if err := fn(q); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return rbErr
		}
		return err
	}

	return tx.Commit(ctx)
}

type GetSessionWithUserRow = db.GetSessionWithUserRow
