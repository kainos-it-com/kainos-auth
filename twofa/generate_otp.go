package twofa

import (
	"crypto/rand"
	"fmt"
	"time"
)

// GenerateOTP generates a one-time password
func (m *Manager) GenerateOTP() (*OTPResult, error) {
	code := make([]byte, 3)
	if _, err := rand.Read(code); err != nil {
		return nil, err
	}

	// Generate 6-digit numeric code
	numCode := (int(code[0])<<16 | int(code[1])<<8 | int(code[2])) % 1000000

	return &OTPResult{
		Code:      fmt.Sprintf("%06d", numCode),
		ExpiresAt: time.Now().Add(m.config.OTPExpiry),
	}, nil
}
