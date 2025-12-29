package admin

import "github.com/kainos-it-com/kainos-auth/store"

// Manager handles admin operations
type Manager struct {
	store  store.Store
	config *Config
}

// New creates a new admin manager
func New(s store.Store, cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Manager{
		store:  s,
		config: cfg,
	}
}
