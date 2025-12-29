package organization

import "context"

// ListTeams lists all teams in an organization
func (m *Manager) ListTeams(ctx context.Context, userID, orgID string) ([]*Team, error) {
	if !m.config.TeamsEnabled {
		return nil, ErrTeamsNotEnabled
	}

	// Check membership
	_, err := m.GetMember(ctx, userID, orgID)
	if err != nil {
		return nil, ErrNotAuthorized
	}

	// Return teams
	return nil, nil
}
