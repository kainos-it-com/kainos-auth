package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	db "github.com/kainos-it-com/kainos-auth/db/sqlc"
)

type LinkAccountInput struct {
	UserID                string
	ProviderID            string
	AccountID             string
	AccessToken           *string
	RefreshToken          *string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 *string
	IDToken               *string
}

func (s *SQLStore) LinkOAuthAccount(ctx context.Context, input LinkAccountInput) (db.Account, error) {
	return s.LinkAccount(ctx, db.LinkAccountParams{
		ID:                    uuid.NewString(),
		UserID:                input.UserID,
		AccountID:             input.AccountID,
		ProviderID:            input.ProviderID,
		AccessToken:           input.AccessToken,
		RefreshToken:          input.RefreshToken,
		AccessTokenExpiresAt:  input.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: input.RefreshTokenExpiresAt,
		Scope:                 input.Scope,
		IDToken:               input.IDToken,
	})
}

func (s *SQLStore) UnlinkOAuthAccount(ctx context.Context, userID, providerID string) error {
	count, err := s.CountUserAccounts(ctx, userID)
	if err != nil {
		return err
	}

	if count <= 1 {
		return ErrCannotUnlinkLastAccount
	}

	return s.UnlinkAccount(ctx, db.UnlinkAccountParams{
		UserID:     userID,
		ProviderID: providerID,
	})
}

func (s *SQLStore) GetCredentialAccount(ctx context.Context, userID string) (*db.Account, error) {
	account, err := s.GetUserCredentialAccount(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (s *SQLStore) HasPassword(ctx context.Context, userID string) (bool, error) {
	account, err := s.GetUserCredentialAccount(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return false, nil
		}
		return false, err
	}
	return account.Password != nil, nil
}

func (s *SQLStore) SetPassword(ctx context.Context, userID, passwordHash string) (db.Account, error) {
	account, err := s.GetUserCredentialAccount(ctx, userID)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return s.CreateAccount(ctx, db.CreateAccountParams{
				ID:         uuid.NewString(),
				UserID:     userID,
				AccountID:  userID,
				ProviderID: "credential",
				Password:   &passwordHash,
			})
		}
		return db.Account{}, err
	}

	return s.UpdateAccountPassword(ctx, db.UpdateAccountPasswordParams{
		ID:       account.ID,
		Password: &passwordHash,
	})
}

func (s *SQLStore) ChangePassword(ctx context.Context, userID, newPasswordHash string, revokeOtherSessions bool, currentSessionID string) error {
	return s.ExecTx(ctx, func(q db.Querier) error {
		_, err := q.SetUserPassword(ctx, db.SetUserPasswordParams{
			UserID:   userID,
			Password: &newPasswordHash,
		})
		if err != nil {
			return err
		}

		if revokeOtherSessions && currentSessionID != "" {
			return q.RevokeOtherSessions(ctx, db.RevokeOtherSessionsParams{
				UserID: userID,
				ID:     currentSessionID,
			})
		}

		return nil
	})
}

func (s *SQLStore) RefreshOAuthTokens(ctx context.Context, accountID string, tokens *OAuthTokens) (db.Account, error) {
	return s.UpdateAccountTokens(ctx, db.UpdateAccountTokensParams{
		ID:                    accountID,
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresAt:  tokens.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
	})
}

func (s *SQLStore) FindAccountByProvider(ctx context.Context, providerID, accountID string) (*db.Account, error) {
	account, err := s.GetAccountByProvider(ctx, db.GetAccountByProviderParams{
		ProviderID: providerID,
		AccountID:  accountID,
	})
	if err != nil {
		return nil, err
	}
	return &account, nil
}

func (s *SQLStore) GetUserProviders(ctx context.Context, userID string) ([]string, error) {
	accounts, err := s.ListUserAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}

	providers := make([]string, len(accounts))
	for i, acc := range accounts {
		providers[i] = acc.ProviderID
	}
	return providers, nil
}

func (s *SQLStore) HasProvider(ctx context.Context, userID, providerID string) (bool, error) {
	accounts, err := s.ListUserAccounts(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, acc := range accounts {
		if acc.ProviderID == providerID {
			return true, nil
		}
	}
	return false, nil
}
