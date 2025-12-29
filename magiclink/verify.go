package magiclink

import (
	"context"
	"fmt"
	"time"

	"github.com/kainos.it.com/kainos-auth/core"
	db "github.com/kainos.it.com/kainos-auth/db/sqlc"
	"github.com/kainos.it.com/kainos-auth/store"
)

// Verify validates a magic link token and returns/creates the user
func (m *Manager) Verify(ctx context.Context, input VerifyInput) (*core.AuthResponse, error) {
	// Try to validate the token
	identifier := fmt.Sprintf("magic_link:%s", input.Email)

	verification, err := m.store.ValidateVerification(ctx, db.ValidateVerificationParams{
		Identifier: identifier,
		Value:      input.Token,
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	if time.Now().After(verification.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Get or create user
	user, err := m.store.GetUserByEmail(ctx, input.Email)
	if err != nil {
		// Create new user
		result, err := m.store.CreateUserWithID(ctx, store.CreateUserInput{
			Email:         input.Email,
			Name:          input.Email, // Default name to email
			EmailVerified: true,        // Magic link verifies email
		})
		if err != nil {
			return nil, err
		}
		user = result
	}

	// Mark email as verified if not already
	if !user.EmailVerified {
		user, err = m.store.UpdateUserFields(ctx, store.UpdateUserInput{
			ID:            user.ID,
			Name:          user.Name,
			Email:         user.Email,
			EmailVerified: true,
			Image:         user.Image,
		})
		if err != nil {
			return nil, err
		}
	}

	// Create session
	session, err := m.store.CreateSessionForUser(ctx, store.CreateSessionInput{
		UserID:    user.ID,
		IPAddress: input.IPAddress,
		UserAgent: input.UserAgent,
	})
	if err != nil {
		return nil, err
	}

	// Consume the verification token
	_ = m.store.ConsumeVerification(ctx, verification.ID)

	return &core.AuthResponse{
		User:    &user,
		Session: &session,
	}, nil
}
