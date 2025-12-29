package admin

import "context"

// BanUser bans a user and revokes all their sessions
func (m *Manager) BanUser(ctx context.Context, adminID string, input BanUserInput) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	// Revoke all sessions
	if err := m.store.RevokeAllUserSessions(ctx, input.UserID); err != nil {
		return err
	}

	// Set ban status (requires ban fields in user table)
	// This is a placeholder - implement based on your schema
	return nil
}
