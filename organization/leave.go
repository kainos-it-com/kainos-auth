package organization

import "context"

// Leave removes the current user from an organization
func (m *Manager) Leave(ctx context.Context, userID, orgID string) error {
	member, err := m.GetMember(ctx, userID, orgID)
	if err != nil {
		return err
	}

	// Owner cannot leave (must transfer ownership first)
	if member.Role == "owner" {
		return ErrOwnerCannotLeave
	}

	// Remove member
	return nil
}
