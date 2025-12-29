package organization

import (
	"context"
	"time"
)

// Create creates a new organization
func (m *Manager) Create(ctx context.Context, input CreateInput) (*CreateResult, error) {
	if !m.config.AllowUserToCreateOrg {
		return nil, ErrOrgCreationDisabled
	}

	// Check organization limit
	if m.config.OrganizationLimit > 0 {
		count, err := m.getUserOrgCount(ctx, input.UserID)
		if err != nil {
			return nil, err
		}
		if count >= m.config.OrganizationLimit {
			return nil, ErrOrgLimitReached
		}
	}

	// Check if slug is taken
	taken, err := m.IsSlugTaken(ctx, input.Slug)
	if err != nil {
		return nil, err
	}
	if taken {
		return nil, ErrSlugTaken
	}

	// Create organization and member in transaction
	// This is a placeholder - implement with actual store methods
	org := &Organization{
		Name:      input.Name,
		Slug:      input.Slug,
		Logo:      input.Logo,
		Metadata:  input.Metadata,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	member := &Member{
		UserID:         input.UserID,
		OrganizationID: org.ID,
		Role:           m.config.CreatorRole,
		CreatedAt:      time.Now(),
	}

	return &CreateResult{
		Organization: org,
		Member:       member,
	}, nil
}

// getUserOrgCount returns the number of organizations a user belongs to
func (m *Manager) getUserOrgCount(ctx context.Context, userID string) (int, error) {
	// Implement based on your store
	return 0, nil
}
