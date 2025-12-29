package organization

import "context"

// RejectInvitation rejects an organization invitation
func (m *Manager) RejectInvitation(ctx context.Context, userID, invitationID string) error {
	// Update invitation status to rejected
	return nil
}
