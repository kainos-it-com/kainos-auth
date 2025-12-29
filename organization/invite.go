package organization

import (
	"context"
	"time"
)

// Invite sends an invitation to join an organization
func (m *Manager) Invite(ctx context.Context, input InviteInput) (*Invitation, error) {
	// Check permission
	if !m.HasPermission(ctx, input.InviterID, input.OrganizationID, "invitation", "create") {
		return nil, ErrNotAuthorized
	}

	// Check invitation limit
	// Check if user is already a member
	// Create invitation

	invitation := &Invitation{
		Email:          input.Email,
		OrganizationID: input.OrganizationID,
		InviterID:      input.InviterID,
		Role:           input.Role,
		Status:         "pending",
		TeamID:         input.TeamID,
		ExpiresAt:      time.Now().Add(m.config.InvitationExpiresIn),
		CreatedAt:      time.Now(),
	}

	return invitation, nil
}
