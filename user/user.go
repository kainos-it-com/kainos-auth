package user

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/core"
	db "github.com/kainos.it.com/kainos-auth/db/sqlc"
	"github.com/kainos.it.com/kainos-auth/password"
	"github.com/kainos.it.com/kainos-auth/store"
)

// Manager handles user operations
type Manager struct {
	store store.Store
}

// New creates a new user manager
func New(s store.Store) *Manager {
	return &Manager{store: s}
}

// Get returns a user by ID
func (m *Manager) Get(ctx context.Context, userID string) (*db.User, error) {
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, core.ErrUserNotFound
	}
	return &user, nil
}

// GetByEmail returns a user by email
func (m *Manager) GetByEmail(ctx context.Context, email string) (*db.User, error) {
	user, err := m.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, core.ErrUserNotFound
	}
	return &user, nil
}

// Update updates user information
func (m *Manager) Update(ctx context.Context, input core.UpdateUserInput) (*db.User, error) {
	user, err := m.store.GetUserByID(ctx, input.UserID)
	if err != nil {
		return nil, core.ErrUserNotFound
	}

	name := user.Name
	if input.Name != nil {
		name = *input.Name
	}

	image := user.Image
	if input.Image != nil {
		image = input.Image
	}

	updated, err := m.store.UpdateUserFields(ctx, store.UpdateUserInput{
		ID:            input.UserID,
		Name:          name,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Image:         image,
	})
	if err != nil {
		return nil, err
	}

	return &updated, nil
}

// Delete deletes a user and all associated data
func (m *Manager) Delete(ctx context.Context, input core.DeleteUserInput) error {
	if input.Password != nil {
		account, err := m.store.GetCredentialAccount(ctx, input.UserID)
		if err == nil && account.Password != nil {
			if !password.Check(*input.Password, *account.Password) {
				return core.ErrPasswordMismatch
			}
		}
	}

	if input.Token != nil {
		_, err := m.store.ValidateDeleteAccount(ctx, input.UserID, *input.Token)
		if err != nil {
			return core.ErrVerificationExpired
		}
	}

	return m.store.DeleteUserWithCleanup(ctx, input.UserID)
}

// RequestDelete creates a delete account verification
func (m *Manager) RequestDelete(ctx context.Context, userID string) (*DeleteRequest, error) {
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, core.ErrUserNotFound
	}

	verification, err := m.store.CreateDeleteAccountVerification(ctx, userID, nil)
	if err != nil {
		return nil, err
	}

	return &DeleteRequest{
		Token:  verification.Value,
		UserID: userID,
		Email:  user.Email,
	}, nil
}

// ListAccounts returns all linked accounts for a user
func (m *Manager) ListAccounts(ctx context.Context, userID string) ([]db.Account, error) {
	return m.store.ListUserAccounts(ctx, userID)
}

// GetWithAccounts returns user with all linked accounts
func (m *Manager) GetWithAccounts(ctx context.Context, userID string) (*store.UserWithAccounts, error) {
	return m.store.GetUserWithAccounts(ctx, userID)
}

// GetWithSessions returns user with all active sessions
func (m *Manager) GetWithSessions(ctx context.Context, userID string) (*store.UserWithSessions, error) {
	return m.store.GetUserWithSessions(ctx, userID)
}

// DeleteRequest contains delete account information
type DeleteRequest struct {
	Token  string
	UserID string
	Email  string
}
