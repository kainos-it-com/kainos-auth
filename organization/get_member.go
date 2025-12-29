package organization

import "context"

// GetMember returns a member by user ID and organization ID
func (m *Manager) GetMember(ctx context.Context, userID, orgID string) (*Member, error) {
	// Implement based on your store
	return nil, nil
}
