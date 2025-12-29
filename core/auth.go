package core

import (
	"time"

	"github.com/kainos-it-com/kainos-auth/store"
)

// Auth is the main authentication instance
type Auth struct {
	Store  store.Store
	Config *Config
}

// Config holds all authentication configuration
type Config struct {
	Session        SessionConfig
	Password       PasswordConfig
	EmailVerify    bool
	TrustedOrigins []string
	Secret         string
}

// SessionConfig configures session behavior
type SessionConfig struct {
	ExpiresIn  time.Duration
	UpdateAge  time.Duration
	FreshAge   time.Duration
	CookieName string
}

// PasswordConfig configures password requirements
type PasswordConfig struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Session: SessionConfig{
			ExpiresIn:  7 * 24 * time.Hour,
			UpdateAge:  24 * time.Hour,
			FreshAge:   24 * time.Hour,
			CookieName: "better_auth_session",
		},
		Password: PasswordConfig{
			MinLength: 8,
		},
		EmailVerify: false,
		Secret:      "",
	}
}

// New creates a new Auth instance
func New(s store.Store, cfg *Config) *Auth {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Auth{
		Store:  s,
		Config: cfg,
	}
}

// Option is a functional option for configuring Auth
type Option func(*Config)

// WithSessionExpiry sets session expiration duration
func WithSessionExpiry(d time.Duration) Option {
	return func(c *Config) {
		c.Session.ExpiresIn = d
	}
}

// WithEmailVerification enables email verification
func WithEmailVerification(enabled bool) Option {
	return func(c *Config) {
		c.EmailVerify = enabled
	}
}

// WithSecret sets the secret key
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithPasswordPolicy sets password requirements
func WithPasswordPolicy(minLen int, upper, lower, number, special bool) Option {
	return func(c *Config) {
		c.Password = PasswordConfig{
			MinLength:      minLen,
			RequireUpper:   upper,
			RequireLower:   lower,
			RequireNumber:  number,
			RequireSpecial: special,
		}
	}
}

// NewWithOptions creates Auth with functional options
func NewWithOptions(s store.Store, opts ...Option) *Auth {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	return New(s, cfg)
}
