package magiclink

import "time"

// Config holds magic link configuration
type Config struct {
	ExpiresIn     time.Duration
	TokenLength   int
	DisableSignUp bool
	CallbackURL   string
}

// DefaultConfig returns sensible magic link defaults
func DefaultConfig() *Config {
	return &Config{
		ExpiresIn:     5 * time.Minute,
		TokenLength:   32,
		DisableSignUp: false,
	}
}
