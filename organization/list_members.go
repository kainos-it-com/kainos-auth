package organization

import "context"

// ListMembers lists all members of an organization
func (m *Manager) ListMembers(ctx context.Context, userID, orgID string, limit, offset int) ([]*Member, error) {
	// Check permission
	// Return members
	return nil, nil
}
