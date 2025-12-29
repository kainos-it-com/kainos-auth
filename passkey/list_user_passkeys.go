package passkey

import "context"

// ListUserPasskeys returns all passkeys for a user
func (m *Manager) ListUserPasskeys(ctx context.Context, userID string) ([]*Passkey, error) {
	// Implement based on your store
	return nil, nil
}
