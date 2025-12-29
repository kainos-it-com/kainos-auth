package organization

import "context"

// Delete deletes an organization
func (m *Manager) Delete(ctx context.Context, userID, orgID string) error {
	// Check permission (only owner can delete)
	member, err := m.GetMember(ctx, userID, orgID)
	if err != nil {
		return err
	}
	if member.Role != "owner" {
		return ErrNotAuthorized
	}

	// Delete organization and all related data
	// Implement based on your store
	return nil
}
