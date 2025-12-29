package password

import (
	"context"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/kainos.it.com/kainos-auth/core"
	"github.com/kainos.it.com/kainos-auth/store"
)

const bcryptCost = 12

// Manager handles password operations
type Manager struct {
	store  store.Store
	config *core.PasswordConfig
}

// New creates a new password manager
func New(s store.Store, cfg *core.PasswordConfig) *Manager {
	return &Manager{
		store:  s,
		config: cfg,
	}
}

// Hash hashes a password using bcrypt
func Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Check verifies a password against a hash
func Check(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Validate checks if a password meets the configured requirements
func (m *Manager) Validate(password string) error {
	if len(password) < m.config.MinLength {
		return core.ErrPasswordTooShort
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if m.config.RequireUpper && !hasUpper {
		return core.ErrPasswordNoUpper
	}
	if m.config.RequireLower && !hasLower {
		return core.ErrPasswordNoLower
	}
	if m.config.RequireNumber && !hasNumber {
		return core.ErrPasswordNoNumber
	}
	if m.config.RequireSpecial && !hasSpecial {
		return core.ErrPasswordNoSpecial
	}

	return nil
}

// Change changes the user's password
func (m *Manager) Change(ctx context.Context, input core.ChangePasswordInput) error {
	account, err := m.store.GetCredentialAccount(ctx, input.UserID)
	if err != nil {
		return core.ErrAccountNotFound
	}

	if account.Password == nil {
		return core.ErrPasswordNotSet
	}

	if !Check(input.CurrentPassword, *account.Password) {
		return core.ErrPasswordMismatch
	}

	if err := m.Validate(input.NewPassword); err != nil {
		return err
	}

	hash, err := Hash(input.NewPassword)
	if err != nil {
		return err
	}

	return m.store.ChangePassword(ctx, input.UserID, hash, input.RevokeOtherSessions, input.CurrentSessionID)
}

// Set sets a password for users without one (OAuth users)
func (m *Manager) Set(ctx context.Context, userID, password string) error {
	if err := m.Validate(password); err != nil {
		return err
	}

	hash, err := Hash(password)
	if err != nil {
		return err
	}

	_, err = m.store.SetPassword(ctx, userID, hash)
	return err
}

// Reset resets password using a verification token
func (m *Manager) Reset(ctx context.Context, input core.ResetPasswordInput) error {
	if err := m.Validate(input.NewPassword); err != nil {
		return err
	}

	hash, err := Hash(input.NewPassword)
	if err != nil {
		return err
	}

	return m.store.ResetPasswordWithToken(ctx, input.Email, input.Token, hash)
}

// RequestReset creates a password reset verification
func (m *Manager) RequestReset(ctx context.Context, email string) (*ResetRequest, error) {
	user, err := m.store.GetUserByEmail(ctx, email)
	if err != nil {
		// Don't reveal if email exists
		return &ResetRequest{Sent: true}, nil
	}

	verification, err := m.store.CreatePasswordReset(ctx, email, nil)
	if err != nil {
		return nil, err
	}

	return &ResetRequest{
		Sent:   true,
		Token:  verification.Value,
		UserID: user.ID,
		Email:  email,
	}, nil
}

// HasPassword checks if user has a credential account with password
func (m *Manager) HasPassword(ctx context.Context, userID string) (bool, error) {
	return m.store.HasPassword(ctx, userID)
}

// ResetRequest contains password reset information
type ResetRequest struct {
	Sent   bool
	Token  string
	UserID string
	Email  string
}
