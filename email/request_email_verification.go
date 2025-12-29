package email

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/core"
)

// VerificationRequest contains email verification information
type VerificationRequest struct {
	Token           string
	UserID          string
	Email           string
	AlreadyVerified bool
}

func (m *Manager) RequestVerification(ctx context.Context, email string) (*VerificationRequest, error) {
	user, err := m.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, core.ErrUserNotFound
	}

	if user.EmailVerified {
		return &VerificationRequest{AlreadyVerified: true}, nil
	}

	verification, err := m.store.CreateEmailVerification(ctx, email, nil)
	if err != nil {
		return nil, err
	}

	return &VerificationRequest{
		Token:  verification.Value,
		UserID: user.ID,
		Email:  email,
	}, nil
}
