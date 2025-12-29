package passkey

import "github.com/kainos.it.com/kainos-auth/store"

// Manager handles passkey/WebAuthn operations
type Manager struct {
	store  store.Store
	config *Config
}

// New creates a new passkey manager
func New(s store.Store, cfg *Config) *Manager {
	return &Manager{
		store:  s,
		config: cfg,
	}
}
