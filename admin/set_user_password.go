package admin

import (
	"context"

	"github.com/kainos-it-com/kainos-auth/password"
)

// SetUserPassword changes a user's password
func (m *Manager) SetUserPassword(ctx context.Context, adminID, userID, newPassword string) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	hash, err := password.Hash(newPassword)
	if err != nil {
		return err
	}

	_, err = m.store.SetPassword(ctx, userID, hash)
	return err
}
