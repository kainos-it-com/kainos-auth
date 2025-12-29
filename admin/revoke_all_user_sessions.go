package admin

import "context"

// RevokeAllUserSessions revokes all sessions for a user
func (m *Manager) RevokeAllUserSessions(ctx context.Context, adminID, userID string) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	return m.store.RevokeAllUserSessions(ctx, userID)
}
