package organization

import "context"

// ListInvitations lists all invitations for an organization
func (m *Manager) ListInvitations(ctx context.Context, userID, orgID string) ([]*Invitation, error) {
	// Check permission
	// Return invitations
	return nil, nil
}

// ListUserInvitations lists all pending invitations for a user
func (m *Manager) ListUserInvitations(ctx context.Context, userID string) ([]*Invitation, error) {
	// Get user email
	// Return pending invitations for that email
	return nil, nil
}
