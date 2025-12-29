package organization

import "context"

// RemoveTeamMember removes a member from a team
func (m *Manager) RemoveTeamMember(ctx context.Context, userID, teamID, targetUserID string) error {
	if !m.config.TeamsEnabled {
		return ErrTeamsNotEnabled
	}

	// Check permission
	// Remove member from team
	return nil
}
