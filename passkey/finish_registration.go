package passkey

import (
	"context"
	"fmt"
	"time"
)

// FinishRegistration completes the passkey registration
func (m *Manager) FinishRegistration(ctx context.Context, input FinishRegistrationInput) (*Passkey, error) {
	// Verify challenge was issued
	_, err := m.store.GetVerificationByIdentifier(ctx, fmt.Sprintf("passkey_reg:%s", input.UserID))
	if err != nil {
		return nil, ErrInvalidChallenge
	}

	// Store passkey
	passkey := &Passkey{
		UserID:       input.UserID,
		Name:         input.Name,
		CredentialID: input.CredentialID,
		PublicKey:    input.PublicKey,
		Counter:      input.Counter,
		DeviceType:   input.DeviceType,
		BackedUp:     input.BackedUp,
		Transports:   input.Transports,
		AAGUID:       input.AAGUID,
		CreatedAt:    time.Now(),
	}

	// Store in database (implement based on your store)
	// This is a placeholder

	return passkey, nil
}
