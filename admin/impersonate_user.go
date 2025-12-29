package admin

import (
	"context"

	"github.com/kainos.it.com/kainos-auth/core"
	"github.com/kainos.it.com/kainos-auth/store"
)

// ImpersonateUser creates a session as another user
func (m *Manager) ImpersonateUser(ctx context.Context, adminID, targetUserID string, ipAddress, userAgent *string) (*core.AuthResponse, error) {
	if !m.IsAdmin(ctx, adminID) {
		return nil, ErrNotAuthorized
	}

	// Check if target is admin and impersonation is not allowed
	if !m.config.AllowImpersonatingAdmins && m.IsAdmin(ctx, targetUserID) {
		return nil, ErrCannotImpersonateAdmin
	}

	// Get target user
	user, err := m.store.GetUserByID(ctx, targetUserID)
	if err != nil {
		return nil, core.ErrUserNotFound
	}

	// Create impersonation session with shorter expiry
	session, err := m.store.CreateSessionForUser(ctx, store.CreateSessionInput{
		UserID:    targetUserID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresIn: &m.config.ImpersonationDuration,
	})
	if err != nil {
		return nil, err
	}

	// Note: You should store impersonatedBy in the session
	// This requires adding the field to your session table

	return &core.AuthResponse{
		User:    &user,
		Session: &session,
	}, nil
}
