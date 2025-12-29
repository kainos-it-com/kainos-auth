package admin

import "context"

// RevokeUserSession revokes a specific session
func (m *Manager) RevokeUserSession(ctx context.Context, adminID, sessionToken string) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	return m.store.RevokeSessionByToken(ctx, sessionToken)
}
