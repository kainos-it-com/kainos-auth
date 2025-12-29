package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	db "github.com/kainos.it.com/kainos-auth/db/sqlc"
)

const (
	DefaultVerificationExpiry = 24 * time.Hour
	EmailVerificationType     = "email_verification"
	PasswordResetType         = "password_reset"
	EmailChangeType           = "email_change"
	DeleteAccountType         = "delete_account"
)

type CreateVerificationInput struct {
	Identifier string
	ExpiresIn  *time.Duration
}

func (s *SQLStore) CreateEmailVerification(ctx context.Context, email string, expiresIn *time.Duration) (db.Verification, error) {
	return s.createVerification(ctx, EmailVerificationType+":"+email, expiresIn)
}

func (s *SQLStore) CreatePasswordReset(ctx context.Context, email string, expiresIn *time.Duration) (db.Verification, error) {
	return s.createVerification(ctx, PasswordResetType+":"+email, expiresIn)
}

func (s *SQLStore) CreateEmailChange(ctx context.Context, userID, newEmail string, expiresIn *time.Duration) (db.Verification, error) {
	return s.createVerification(ctx, EmailChangeType+":"+userID+":"+newEmail, expiresIn)
}

func (s *SQLStore) CreateDeleteAccountVerification(ctx context.Context, userID string, expiresIn *time.Duration) (db.Verification, error) {
	return s.createVerification(ctx, DeleteAccountType+":"+userID, expiresIn)
}

func (s *SQLStore) createVerification(ctx context.Context, identifier string, expiresIn *time.Duration) (db.Verification, error) {
	token, err := generateVerificationToken()
	if err != nil {
		return db.Verification{}, err
	}

	duration := DefaultVerificationExpiry
	if expiresIn != nil {
		duration = *expiresIn
	}

	return s.CreateVerification(ctx, db.CreateVerificationParams{
		ID:         uuid.NewString(),
		Identifier: identifier,
		Value:      token,
		ExpiresAt:  time.Now().Add(duration),
	})
}

func (s *SQLStore) ValidateEmailVerification(ctx context.Context, email, token string) (*db.Verification, error) {
	return s.validateVerification(ctx, EmailVerificationType+":"+email, token)
}

func (s *SQLStore) ValidatePasswordReset(ctx context.Context, email, token string) (*db.Verification, error) {
	return s.validateVerification(ctx, PasswordResetType+":"+email, token)
}

func (s *SQLStore) ValidateEmailChange(ctx context.Context, userID, newEmail, token string) (*db.Verification, error) {
	return s.validateVerification(ctx, EmailChangeType+":"+userID+":"+newEmail, token)
}

func (s *SQLStore) ValidateDeleteAccount(ctx context.Context, userID, token string) (*db.Verification, error) {
	return s.validateVerification(ctx, DeleteAccountType+":"+userID, token)
}

func (s *SQLStore) validateVerification(ctx context.Context, identifier, token string) (*db.Verification, error) {
	v, err := s.ValidateVerification(ctx, db.ValidateVerificationParams{
		Identifier: identifier,
		Value:      token,
	})
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (s *SQLStore) ConsumeVerification(ctx context.Context, id string) error {
	return s.DeleteVerification(ctx, id)
}

func (s *SQLStore) CleanupExpiredVerifications(ctx context.Context) error {
	return s.DeleteExpiredVerifications(ctx)
}

func (s *SQLStore) InvalidateUserVerifications(ctx context.Context, identifier string) error {
	return s.DeleteVerificationByIdentifier(ctx, identifier)
}

func (s *SQLStore) VerifyEmailWithToken(ctx context.Context, email, token string) error {
	return s.ExecTx(ctx, func(q db.Querier) error {
		v, err := q.ValidateVerification(ctx, db.ValidateVerificationParams{
			Identifier: EmailVerificationType + ":" + email,
			Value:      token,
		})
		if err != nil {
			return err
		}

		user, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			return err
		}

		_, err = q.VerifyUserEmail(ctx, user.ID)
		if err != nil {
			return err
		}

		return q.DeleteVerification(ctx, v.ID)
	})
}

func (s *SQLStore) ResetPasswordWithToken(ctx context.Context, email, token, newPasswordHash string) error {
	return s.ExecTx(ctx, func(q db.Querier) error {
		v, err := q.ValidateVerification(ctx, db.ValidateVerificationParams{
			Identifier: PasswordResetType + ":" + email,
			Value:      token,
		})
		if err != nil {
			return err
		}

		user, err := q.GetUserByEmail(ctx, email)
		if err != nil {
			return err
		}

		_, err = q.SetUserPassword(ctx, db.SetUserPasswordParams{
			UserID:   user.ID,
			Password: &newPasswordHash,
		})
		if err != nil {
			return err
		}

		if err := q.RevokeUserSessions(ctx, user.ID); err != nil {
			return err
		}

		return q.DeleteVerification(ctx, v.ID)
	})
}

func generateVerificationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
