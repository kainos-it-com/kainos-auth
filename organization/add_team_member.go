package organization

import "context"

// AddTeamMember adds a member to a team
func (m *Manager) AddTeamMember(ctx context.Context, userID, teamID, targetUserID string) (*TeamMember, error) {
	if !m.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}

	// Check permission
	// Add member to team
	return nil, nil
}
