package session

import (
	"context"
	"time"

	"github.com/kainos-it-com/kainos-auth/core"
	db "github.com/kainos-it-com/kainos-auth/db/sqlc"
	"github.com/kainos-it-com/kainos-auth/store"
)

// Manager handles session operations
type Manager struct {
	store  store.Store
	config *core.SessionConfig
}

// New creates a new session manager
func New(s store.Store, cfg *core.SessionConfig) *Manager {
	return &Manager{
		store:  s,
		config: cfg,
	}
}

// Create creates a new session for a user
func (m *Manager) Create(ctx context.Context, userID string, ipAddress, userAgent *string) (*db.Session, error) {
	session, err := m.store.CreateSessionForUser(ctx, store.CreateSessionInput{
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresIn: &m.config.ExpiresIn,
	})
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// Validate validates a session token and returns the session with user
func (m *Manager) Validate(ctx context.Context, token string) (*core.AuthResponse, error) {
	result, err := m.store.GetFullSession(ctx, token)
	if err != nil {
		return nil, core.ErrSessionNotFound
	}

	if time.Now().After(result.Session.ExpiresAt) {
		return nil, core.ErrSessionExpired
	}

	return &core.AuthResponse{
		User:    &result.User,
		Session: &result.Session,
	}, nil
}

// Refresh extends the session expiry if updateAge has passed
func (m *Manager) Refresh(ctx context.Context, token string) (*core.AuthResponse, error) {
	session, err := m.store.GetSessionByToken(ctx, token)
	if err != nil {
		return nil, core.ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, core.ErrSessionExpired
	}

	timeSinceUpdate := time.Since(session.UpdatedAt)
	if timeSinceUpdate < m.config.UpdateAge {
		user, err := m.store.GetUserByID(ctx, session.UserID)
		if err != nil {
			return nil, err
		}
		return &core.AuthResponse{User: &user, Session: &session}, nil
	}

	updated, err := m.store.RefreshSession(ctx, session.ID, m.config.ExpiresIn)
	if err != nil {
		return nil, err
	}

	user, err := m.store.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	return &core.AuthResponse{User: &user, Session: &updated}, nil
}

// Revoke revokes a session by token
func (m *Manager) Revoke(ctx context.Context, token string) error {
	return m.store.RevokeSessionByToken(ctx, token)
}

// RevokeByID revokes a session by ID
func (m *Manager) RevokeByID(ctx context.Context, sessionID string) error {
	return m.store.RevokeSession(ctx, sessionID)
}

// RevokeAll revokes all sessions for a user
func (m *Manager) RevokeAll(ctx context.Context, userID string) error {
	return m.store.RevokeAllUserSessions(ctx, userID)
}

// RevokeOthers revokes all sessions except the current one
func (m *Manager) RevokeOthers(ctx context.Context, userID, currentSessionID string) error {
	return m.store.RevokeOtherUserSessions(ctx, userID, currentSessionID)
}

// List returns all active sessions for a user
func (m *Manager) List(ctx context.Context, userID string) ([]db.Session, error) {
	return m.store.ListActiveSessions(ctx, userID)
}

// IsFresh checks if the session was created within the freshAge
func (m *Manager) IsFresh(ctx context.Context, token string) (bool, error) {
	session, err := m.store.GetSessionByToken(ctx, token)
	if err != nil {
		return false, core.ErrSessionNotFound
	}
	return time.Since(session.CreatedAt) < m.config.FreshAge, nil
}

// RequireFresh returns an error if the session is not fresh
func (m *Manager) RequireFresh(ctx context.Context, token string) error {
	fresh, err := m.IsFresh(ctx, token)
	if err != nil {
		return err
	}
	if !fresh {
		return core.ErrSessionNotFresh
	}
	return nil
}

// Cleanup removes expired sessions
func (m *Manager) Cleanup(ctx context.Context) error {
	return m.store.CleanupExpiredSessions(ctx)
}

// Count returns the number of active sessions for a user
func (m *Manager) Count(ctx context.Context, userID string) (int64, error) {
	return m.store.GetActiveSessionCount(ctx, userID)
}
