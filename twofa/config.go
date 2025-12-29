package twofa

import "time"

// Config holds 2FA configuration
type Config struct {
	Issuer           string
	TOTPPeriod       int           // seconds, default 30
	TOTPDigits       int           // default 6
	BackupCodeCount  int           // default 10
	TrustedDeviceTTL time.Duration // default 30 days
	OTPExpiry        time.Duration // default 5 minutes
}

// DefaultConfig returns sensible 2FA defaults
func DefaultConfig(issuer string) *Config {
	return &Config{
		Issuer:           issuer,
		TOTPPeriod:       30,
		TOTPDigits:       6,
		BackupCodeCount:  10,
		TrustedDeviceTTL: 30 * 24 * time.Hour,
		OTPExpiry:        5 * time.Minute,
	}
}
