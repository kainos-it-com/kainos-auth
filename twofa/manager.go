package twofa

import "github.com/kainos-it-com/kainos-auth/store"

// Manager handles two-factor authentication operations
type Manager struct {
	store  store.Store
	config *Config
}

// New creates a new 2FA manager
func New(s store.Store, cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig("kainos-auth")
	}
	return &Manager{
		store:  s,
		config: cfg,
	}
}
