package admin

import (
	"context"

	"github.com/kainos-it-com/kainos-auth/password"
	"github.com/kainos-it-com/kainos-auth/store"
)

// CreateUser creates a new user as admin
func (m *Manager) CreateUser(ctx context.Context, adminID string, input CreateUserInput) (*store.UserWithAccounts, error) {
	if !m.IsAdmin(ctx, adminID) {
		return nil, ErrNotAuthorized
	}

	// Hash password
	hash, err := password.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	// Create user with credential
	result, err := m.store.CreateUserWithCredential(ctx, store.CreateUserInput{
		Name:          input.Name,
		Email:         input.Email,
		EmailVerified: true, // Admin-created users are verified
	}, hash)
	if err != nil {
		return nil, err
	}

	return result, nil
}
