package passkey

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/kainos-it-com/kainos-auth/core"
	db "github.com/kainos-it-com/kainos-auth/db/sqlc"
)

// BeginRegistration starts the passkey registration process
func (m *Manager) BeginRegistration(ctx context.Context, userID string, authenticatorAttachment string) (*RegistrationOptions, error) {
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, core.ErrUserNotFound
	}

	// Generate challenge
	challenge, err := generateChallenge(32)
	if err != nil {
		return nil, err
	}

	// Store challenge for verification
	_, err = m.store.CreateVerification(ctx, db.CreateVerificationParams{
		ID:         uuid.NewString(),
		Identifier: fmt.Sprintf("passkey_reg:%s", userID),
		Value:      challenge,
		ExpiresAt:  time.Now().Add(m.config.ChallengeExpiry),
	})
	if err != nil {
		return nil, err
	}

	options := &RegistrationOptions{
		Challenge: challenge,
		RP: RelyingParty{
			ID:   m.config.RPID,
			Name: m.config.RPName,
		},
		User: UserEntity{
			ID:          base64.URLEncoding.EncodeToString([]byte(userID)),
			Name:        user.Email,
			DisplayName: user.Name,
		},
		PubKeyCredParams: []PubKeyCredParam{
			{Type: "public-key", Alg: -7},   // ES256
			{Type: "public-key", Alg: -257}, // RS256
		},
		Timeout:     int64(m.config.Timeout.Milliseconds()),
		Attestation: m.config.AttestationPreference,
	}

	if authenticatorAttachment != "" {
		options.AuthenticatorSelection = &AuthenticatorSelection{
			AuthenticatorAttachment: authenticatorAttachment,
			ResidentKey:             "preferred",
			UserVerification:        m.config.UserVerification,
		}
	}

	return options, nil
}
