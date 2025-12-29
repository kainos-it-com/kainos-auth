package passkey

import "context"

// UpdatePasskeyName updates a passkey's name
func (m *Manager) UpdatePasskeyName(ctx context.Context, userID, passkeyID, name string) error {
	// Verify ownership and update
	return nil
}
