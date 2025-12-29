package admin

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/store"
)

// ListUserSessions lists all sessions for a user
func (m *Manager) ListUserSessions(ctx context.Context, adminID, userID string) (*store.UserWithSessions, error) {
	if !m.IsAdmin(ctx, adminID) {
		return nil, ErrNotAuthorized
	}

	return m.store.GetUserWithSessions(ctx, userID)
}
