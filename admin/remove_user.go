package admin

import "context"

// RemoveUser permanently deletes a user
func (m *Manager) RemoveUser(ctx context.Context, adminID, userID string) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	return m.store.DeleteUserWithCleanup(ctx, userID)
}
