package organization

import "context"

// Update updates an organization
func (m *Manager) Update(ctx context.Context, userID string, input UpdateInput) (*Organization, error) {
	// Check permission
	if !m.HasPermission(ctx, userID, input.OrganizationID, "organization", "update") {
		return nil, ErrNotAuthorized
	}

	// Implement update logic
	return nil, nil
}
