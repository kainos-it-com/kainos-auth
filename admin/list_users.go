package admin

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/store"
)

// ListUsers lists all users with pagination
func (m *Manager) ListUsers(ctx context.Context, adminID string, input ListUsersInput) (*store.PaginatedUsers, error) {
	if !m.IsAdmin(ctx, adminID) {
		return nil, ErrNotAuthorized
	}

	if input.Limit == 0 {
		input.Limit = 100
	}

	return m.store.ListUsersPaginated(ctx, input.Offset/input.Limit+1, input.Limit)
}
