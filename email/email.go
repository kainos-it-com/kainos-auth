package email

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/core"
	"github.com/kainos.it.com/kainos-auth/store"
)

// Manager handles email verification and change operations
type Manager struct {
	store store.Store
}

// New creates a new email manager
func New(s store.Store) *Manager {
	return &Manager{store: s}
}

// RequestVerification creates an email verification token

// Verify verifies a user's email with a token
func (m *Manager) Verify(ctx context.Context, email, token string) error {
	return m.store.VerifyEmailWithToken(ctx, email, token)
}

// Change changes the user's email after verification
func (m *Manager) Change(ctx context.Context, input core.ChangeEmailInput) error {
	_, err := m.store.ValidateEmailChange(ctx, input.UserID, input.NewEmail, input.Token)
	if err != nil {
		return core.ErrVerificationExpired
	}

	_, err = m.store.ChangeUserEmail(ctx, input.UserID, input.NewEmail, true)
	return err
}


