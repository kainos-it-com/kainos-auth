package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	db "github.com/kainos-it-com/kainos-auth/db/sqlc"
)

type CreateUserInput struct {
	Name          string
	Email         string
	EmailVerified bool
	Image         *string
}

type UpdateUserInput struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         *string
}

func (s *SQLStore) CreateUserWithID(ctx context.Context, input CreateUserInput) (db.User, error) {
	return s.CreateUser(ctx, db.CreateUserParams{
		ID:            uuid.NewString(),
		Name:          input.Name,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		Image:         input.Image,
	})
}

func (s *SQLStore) UpdateUserFields(ctx context.Context, input UpdateUserInput) (db.User, error) {
	return s.UpdateUser(ctx, db.UpdateUserParams{
		ID:            input.ID,
		Name:          input.Name,
		Email:         input.Email,
		EmailVerified: input.EmailVerified,
		Image:         input.Image,
	})
}

func (s *SQLStore) ChangeUserEmail(ctx context.Context, userID, newEmail string, verified bool) (db.User, error) {
	return s.UpdateUserEmail(ctx, db.UpdateUserEmailParams{
		ID:            userID,
		Email:         newEmail,
		EmailVerified: verified,
	})
}

func (s *SQLStore) DeleteUserWithCleanup(ctx context.Context, userID string) error {
	return s.ExecTx(ctx, func(q db.Querier) error {
		if err := q.RevokeUserSessions(ctx, userID); err != nil {
			return err
		}
		if err := q.DeleteUserAccounts(ctx, userID); err != nil {
			return err
		}
		return q.DeleteUser(ctx, userID)
	})
}

type UserWithAccounts struct {
	User     db.User
	Accounts []db.Account
}

func (s *SQLStore) GetUserWithAccounts(ctx context.Context, userID string) (*UserWithAccounts, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	accounts, err := s.ListUserAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &UserWithAccounts{
		User:     user,
		Accounts: accounts,
	}, nil
}

type UserWithSessions struct {
	User     db.User
	Sessions []db.Session
}

func (s *SQLStore) GetUserWithSessions(ctx context.Context, userID string) (*UserWithSessions, error) {
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessions, err := s.ListActiveSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &UserWithSessions{
		User:     user,
		Sessions: sessions,
	}, nil
}

type PaginatedUsers struct {
	Users      []db.User
	TotalCount int64
	Page       int32
	PageSize   int32
}

func (s *SQLStore) ListUsersPaginated(ctx context.Context, page, pageSize int32) (*PaginatedUsers, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	offset := (page - 1) * pageSize

	users, err := s.ListUsers(ctx, db.ListUsersParams{
		Limit:  pageSize,
		Offset: offset,
	})
	if err != nil {
		return nil, err
	}

	total, err := s.CountUsers(ctx)
	if err != nil {
		return nil, err
	}

	return &PaginatedUsers{
		Users:      users,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	}, nil
}

func (s *SQLStore) IsEmailTaken(ctx context.Context, email string) (bool, error) {
	_, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

type UserStats struct {
	TotalUsers    int64
	TotalSessions int64
	TotalAccounts int64
}

func (s *SQLStore) GetUserStats(ctx context.Context, userID string) (*UserStats, error) {
	sessions, err := s.CountUserSessions(ctx, userID)
	if err != nil {
		return nil, err
	}

	accounts, err := s.CountUserAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &UserStats{
		TotalSessions: sessions,
		TotalAccounts: accounts,
	}, nil
}

func (s *SQLStore) CreateUserWithCredential(ctx context.Context, input CreateUserInput, passwordHash string) (*UserWithAccounts, error) {
	var result *UserWithAccounts

	err := s.ExecTx(ctx, func(q db.Querier) error {
		userID := uuid.NewString()

		user, err := q.CreateUser(ctx, db.CreateUserParams{
			ID:            userID,
			Name:          input.Name,
			Email:         input.Email,
			EmailVerified: input.EmailVerified,
			Image:         input.Image,
		})
		if err != nil {
			return err
		}

		account, err := q.CreateAccount(ctx, db.CreateAccountParams{
			ID:         uuid.NewString(),
			UserID:     userID,
			AccountID:  userID,
			ProviderID: "credential",
			Password:   &passwordHash,
		})
		if err != nil {
			return err
		}

		result = &UserWithAccounts{
			User:     user,
			Accounts: []db.Account{account},
		}
		return nil
	})

	return result, err
}

func (s *SQLStore) CreateUserWithOAuth(ctx context.Context, input CreateUserInput, providerID, accountID string, tokens *OAuthTokens) (*UserWithAccounts, error) {
	var result *UserWithAccounts

	err := s.ExecTx(ctx, func(q db.Querier) error {
		userID := uuid.NewString()

		user, err := q.CreateUser(ctx, db.CreateUserParams{
			ID:            userID,
			Name:          input.Name,
			Email:         input.Email,
			EmailVerified: input.EmailVerified,
			Image:         input.Image,
		})
		if err != nil {
			return err
		}

		account, err := q.CreateAccount(ctx, db.CreateAccountParams{
			ID:                    uuid.NewString(),
			UserID:                userID,
			AccountID:             accountID,
			ProviderID:            providerID,
			AccessToken:           tokens.AccessToken,
			RefreshToken:          tokens.RefreshToken,
			AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
			RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
			Scope:                 tokens.Scope,
			IDToken:               tokens.IDToken,
		})
		if err != nil {
			return err
		}

		result = &UserWithAccounts{
			User:     user,
			Accounts: []db.Account{account},
		}
		return nil
	})

	return result, err
}

type OAuthTokens struct {
	AccessToken           *string
	RefreshToken          *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string
	IDToken               *string
}
