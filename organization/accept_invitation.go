package organization

import "context"

// AcceptInvitation accepts an organization invitation
func (m *Manager) AcceptInvitation(ctx context.Context, userID, invitationID string) (*Member, error) {
	// Get invitation
	// Verify it's for this user's email
	// Check not expired
	// Create member
	// Update invitation status
	return nil, nil
}
