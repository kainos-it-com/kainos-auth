package magiclink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	db "github.com/kainos-it-com/kainos-auth/db/sqlc"
)

// Send creates a magic link token for the given email
func (m *Manager) Send(ctx context.Context, input SendInput) (*SendResult, error) {
	// Check if user exists
	user, err := m.store.GetUserByEmail(ctx, input.Email)
	isNewUser := err != nil

	if isNewUser && m.config.DisableSignUp {
		return nil, ErrSignUpDisabled
	}

	// Generate token
	token, err := generateToken(m.config.TokenLength)
	if err != nil {
		return nil, err
	}

	// Store verification
	expiresAt := time.Now().Add(m.config.ExpiresIn)
	identifier := fmt.Sprintf("magic_link:%s", input.Email)

	// If new user, include name in identifier for later registration
	if isNewUser && input.Name != "" {
		identifier = fmt.Sprintf("magic_link:%s:%s", input.Email, input.Name)
	}

	_, err = m.store.CreateVerification(ctx, db.CreateVerificationParams{
		ID:         uuid.NewString(),
		Identifier: identifier,
		Value:      token,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		return nil, err
	}

	// Build callback URL
	callbackURL := input.CallbackURL
	if callbackURL == "" {
		callbackURL = m.config.CallbackURL
	}

	url := fmt.Sprintf("%s?token=%s&email=%s", callbackURL, token, input.Email)

	return &SendResult{
		Token:     token,
		URL:       url,
		ExpiresAt: expiresAt,
		IsNewUser: isNewUser || user.ID == "",
	}, nil
}

func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
