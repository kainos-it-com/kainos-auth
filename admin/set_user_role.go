package admin

import "context"

// SetUserRole changes a user's role
func (m *Manager) SetUserRole(ctx context.Context, adminID, userID, role string) error {
	if !m.IsAdmin(ctx, adminID) {
		return ErrNotAuthorized
	}

	// Implementation depends on how roles are stored
	// This is a placeholder for role management
	return nil
}
