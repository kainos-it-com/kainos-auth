package organization

import "github.com/kainos.it.com/kainos-auth/store"

// Manager handles organization operations
type Manager struct {
	store  store.Store
	config *Config
}

// New creates a new organization manager
func New(s store.Store, cfg *Config) *Manager {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Manager{
		store:  s,
		config: cfg,
	}
}
