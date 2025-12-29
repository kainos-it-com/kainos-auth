package magiclink

import "github.com/kainos-it-com/kainos-auth/store"

// Manager handles magic link authentication
type Manager struct {
	store  store.Store
	config *Config
}

// New creates a new magic link manager
func New(s store.Store, cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Manager{
		store:  s,
		config: cfg,
	}
}
