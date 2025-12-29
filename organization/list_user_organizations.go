package organization

import "context"

// ListUserOrganizations returns all organizations a user belongs to
func (m *Manager) ListUserOrganizations(ctx context.Context, userID string) ([]*Organization, error) {
	// Implement based on your store
	return nil, nil
}
