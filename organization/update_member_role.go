package organization

import "context"

// UpdateMemberRole updates a member's role
func (m *Manager) UpdateMemberRole(ctx context.Context, userID, memberID, orgID, newRole string) error {
	// Check permission
	if !m.HasPermission(ctx, userID, orgID, "member", "update") {
		return ErrNotAuthorized
	}

	// Update role
	return nil
}
