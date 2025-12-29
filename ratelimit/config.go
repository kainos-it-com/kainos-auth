package ratelimit

import "time"

// Config holds rate limit configuration
type Config struct {
	// Default limits
	DefaultLimit  int           // requests per window
	DefaultWindow time.Duration // time window

	// Endpoint-specific limits
	EndpointLimits map[string]*EndpointLimit

	// Storage backend
	Storage Storage
}

// EndpointLimit defines rate limits for a specific endpoint
type EndpointLimit struct {
	Limit  int
	Window time.Duration
}

// DefaultConfig returns sensible rate limit defaults
func DefaultConfig() *Config {
	return &Config{
		DefaultLimit:  100,
		DefaultWindow: time.Minute,
		EndpointLimits: map[string]*EndpointLimit{
			"sign-in":         {Limit: 5, Window: time.Minute},
			"sign-up":         {Limit: 3, Window: time.Minute},
			"forgot-password": {Limit: 3, Window: time.Minute},
			"verify-email":    {Limit: 5, Window: time.Minute},
			"magic-link":      {Limit: 3, Window: time.Minute},
			"2fa-verify":      {Limit: 5, Window: time.Minute},
		},
		Storage: NewMemoryStorage(),
	}
}
