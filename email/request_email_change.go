package email

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/core"
)

// ChangeRequest contains email change information
type ChangeRequest struct {
	Token        string
	UserID       string
	CurrentEmail string
	NewEmail     string
}

// RequestChange creates an email change verification
func (m *Manager) RequestChange(ctx context.Context, userID, newEmail string) (*ChangeRequest, error) {
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, core.ErrUserNotFound
	}

	exists, err := m.store.IsEmailTaken(ctx, newEmail)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, core.ErrEmailAlreadyExists
	}

	verification, err := m.store.CreateEmailChange(ctx, userID, newEmail, nil)
	if err != nil {
		return nil, err
	}

	return &ChangeRequest{
		Token:        verification.Value,
		UserID:       userID,
		CurrentEmail: user.Email,
		NewEmail:     newEmail,
	}, nil
}
