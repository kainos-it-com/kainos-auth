package admin

import "context"

// UnbanUser removes a ban from a user
func (m *Manager) UnbanUser(ctx context.Context, adminID, userID string) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	// Remove ban status
	// This is a placeholder - implement based on your schema
	return nil
}
