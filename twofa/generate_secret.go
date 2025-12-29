package twofa

import (
	"crypto/rand"
	"encoding/base32"
)

// GenerateSecret generates a new TOTP secret
func (m *Manager) GenerateSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}
