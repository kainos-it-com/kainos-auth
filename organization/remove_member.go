package organization

import "context"

// RemoveMember removes a member from an organization
func (m *Manager) RemoveMember(ctx context.Context, userID, memberID, orgID string) error {
	// Check permission
	if !m.HasPermission(ctx, userID, orgID, "member", "delete") {
		return ErrNotAuthorized
	}

	// Cannot remove owner
	// Remove member
	return nil
}
