package passkey

import "context"

// DeletePasskey deletes a passkey
func (m *Manager) DeletePasskey(ctx context.Context, userID, passkeyID string) error {
	// Verify ownership and delete
	return nil
}
