package store

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	db "github.com/kainos.it.com/kainos-auth/db/sqlc"
)

const (
	DefaultSessionDuration = 7 * 24 * time.Hour
	DefaultTokenLength     = 32
)

type CreateSessionInput struct {
	UserID    string
	IPAddress *string
	UserAgent *string
	ExpiresIn *time.Duration
}

func (s *SQLStore) CreateSessionForUser(ctx context.Context, input CreateSessionInput) (db.Session, error) {
	token, err := generateToken(DefaultTokenLength)
	if err != nil {
		return db.Session{}, err
	}

	duration := DefaultSessionDuration
	if input.ExpiresIn != nil {
		duration = *input.ExpiresIn
	}

	return s.CreateSession(ctx, db.CreateSessionParams{
		ID:        uuid.NewString(),
		UserID:    input.UserID,
		Token:     token,
		ExpiresAt: time.Now().Add(duration),
		IpAddress: input.IPAddress,
		UserAgent: input.UserAgent,
	})
}

func (s *SQLStore) ValidateSession(ctx context.Context, token string) (*db.GetSessionWithUserRow, error) {
	session, err := s.GetSessionWithUser(ctx, token)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (s *SQLStore) RefreshSession(ctx context.Context, sessionID string, duration time.Duration) (db.Session, error) {
	return s.UpdateSessionExpiry(ctx, db.UpdateSessionExpiryParams{
		ID:        sessionID,
		ExpiresAt: time.Now().Add(duration),
	})
}

func (s *SQLStore) RevokeAllUserSessions(ctx context.Context, userID string) error {
	return s.RevokeUserSessions(ctx, userID)
}

func (s *SQLStore) RevokeOtherUserSessions(ctx context.Context, userID, currentSessionID string) error {
	return s.RevokeOtherSessions(ctx, db.RevokeOtherSessionsParams{
		UserID: userID,
		ID:     currentSessionID,
	})
}

func (s *SQLStore) GetActiveSessionCount(ctx context.Context, userID string) (int64, error) {
	return s.CountUserSessions(ctx, userID)
}

func (s *SQLStore) CleanupExpiredSessions(ctx context.Context) error {
	return s.DeleteExpiredSessions(ctx)
}

type SessionWithUser struct {
	Session db.Session
	User    db.User
}

func (s *SQLStore) GetFullSession(ctx context.Context, token string) (*SessionWithUser, error) {
	row, err := s.GetSessionWithUser(ctx, token)
	if err != nil {
		return nil, err
	}

	return &SessionWithUser{
		Session: db.Session{
			ID:        row.ID,
			UserID:    row.UserID,
			Token:     row.Token,
			ExpiresAt: row.ExpiresAt,
			IpAddress: row.IpAddress,
			UserAgent: row.UserAgent,
			CreatedAt: row.CreatedAt,
			UpdatedAt: row.UpdatedAt,
		},
		User: db.User{
			ID:            row.UserID,
			Name:          row.UserName,
			Email:         row.UserEmail,
			EmailVerified: row.UserEmailVerified,
			Image:         row.UserImage,
		},
	}, nil
}

func (s *SQLStore) IsSessionFresh(ctx context.Context, token string, freshAge time.Duration) (bool, error) {
	session, err := s.GetSessionByToken(ctx, token)
	if err != nil {
		return false, err
	}

	return time.Since(session.CreatedAt) < freshAge, nil
}

func generateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
