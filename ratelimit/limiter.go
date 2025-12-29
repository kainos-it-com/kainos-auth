package ratelimit

import "sync"

// Limiter handles rate limiting
type Limiter struct {
	config  *Config
	storage Storage
	mu      sync.RWMutex
}

// New creates a new rate limiter
func New(cfg *Config) *Limiter {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Storage == nil {
		cfg.Storage = NewMemoryStorage()
	}
	return &Limiter{
		config:  cfg,
		storage: cfg.Storage,
	}
}
