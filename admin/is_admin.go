package admin

import "context"

// IsAdmin checks if a user is an admin
func (m *Manager) IsAdmin(ctx context.Context, userID string) bool {
	// Check if user ID is in admin list
	for _, id := range m.config.AdminUserIDs {
		if id == userID {
			return true
		}
	}

	// Check user role
	user, err := m.store.GetUserByID(ctx, userID)
	if err != nil {
		return false
	}

	// Check if user has admin role (assuming role is stored in user metadata or separate table)
	for _, role := range m.config.AdminRoles {
		if m.hasRole(ctx, user.ID, role) {
			return true
		}
	}

	return false
}

// hasRole checks if user has a specific role
func (m *Manager) hasRole(ctx context.Context, userID, role string) bool {
	// This would check a roles table or user metadata
	// For now, return false - implement based on your role storage
	return false
}
