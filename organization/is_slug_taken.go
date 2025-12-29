package organization

import "context"

// IsSlugTaken checks if an organization slug is already in use
func (m *Manager) IsSlugTaken(ctx context.Context, slug string) (bool, error) {
	// Implement based on your store
	return false, nil
}
