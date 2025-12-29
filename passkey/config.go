package passkey

import "time"

// Config holds passkey configuration
type Config struct {
	RPID                  string // Relying Party ID (your domain)
	RPName                string // Human-readable name
	RPOrigin              string // Origin URL
	AttestationPreference string // "none", "indirect", "direct"
	UserVerification      string // "required", "preferred", "discouraged"
	Timeout               time.Duration
	ChallengeExpiry       time.Duration
}

// DefaultConfig returns sensible passkey defaults
func DefaultConfig(rpID, rpName, origin string) *Config {
	return &Config{
		RPID:                  rpID,
		RPName:                rpName,
		RPOrigin:              origin,
		AttestationPreference: "none",
		UserVerification:      "preferred",
		Timeout:               60 * time.Second,
		ChallengeExpiry:       5 * time.Minute,
	}
}
