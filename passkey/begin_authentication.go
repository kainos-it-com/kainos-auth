package passkey

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	db "github.com/kainos.it.com/kainos-auth/db/sqlc"
)

// BeginAuthentication starts the passkey authentication process
func (m *Manager) BeginAuthentication(ctx context.Context, userID string) (*AuthenticationOptions, error) {
	// Generate challenge
	challenge, err := generateChallenge(32)
	if err != nil {
		return nil, err
	}

	// Store challenge
	identifier := "passkey_auth:anonymous"
	if userID != "" {
		identifier = fmt.Sprintf("passkey_auth:%s", userID)
	}

	_, err = m.store.CreateVerification(ctx, db.CreateVerificationParams{
		ID:         uuid.NewString(),
		Identifier: identifier,
		Value:      challenge,
		ExpiresAt:  time.Now().Add(m.config.ChallengeExpiry),
	})
	if err != nil {
		return nil, err
	}

	options := &AuthenticationOptions{
		Challenge:        challenge,
		Timeout:          int64(m.config.Timeout.Milliseconds()),
		RPID:             m.config.RPID,
		UserVerification: m.config.UserVerification,
	}

	// If user specified, get their passkeys
	if userID != "" {
		passkeys, err := m.ListUserPasskeys(ctx, userID)
		if err == nil && len(passkeys) > 0 {
			options.AllowCredentials = make([]AllowCredential, len(passkeys))
			for i, pk := range passkeys {
				options.AllowCredentials[i] = AllowCredential{
					Type:       "public-key",
					ID:         pk.CredentialID,
					Transports: pk.Transports,
				}
			}
		}
	}

	return options, nil
}
