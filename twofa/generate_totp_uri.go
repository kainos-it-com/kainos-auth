package twofa

import "fmt"

// GenerateTOTPURI generates the otpauth:// URI for authenticator apps
func (m *Manager) GenerateTOTPURI(secret, email string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		m.config.Issuer,
		email,
		secret,
		m.config.Issuer,
		m.config.TOTPDigits,
		m.config.TOTPPeriod,
	)
}
