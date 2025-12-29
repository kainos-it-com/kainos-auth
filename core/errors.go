package core

import "errors"

var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token expired")

	// Password errors
	ErrPasswordTooShort  = errors.New("password too short")
	ErrPasswordNoUpper   = errors.New("password must contain uppercase letter")
	ErrPasswordNoLower   = errors.New("password must contain lowercase letter")
	ErrPasswordNoNumber  = errors.New("password must contain number")
	ErrPasswordNoSpecial = errors.New("password must contain special character")
	ErrPasswordMismatch  = errors.New("current password is incorrect")
	ErrPasswordNotSet    = errors.New("password not set for this account")

	// OAuth errors
	ErrOAuthStateMismatch = errors.New("oauth state mismatch")
	ErrOAuthCodeInvalid   = errors.New("oauth code invalid")
	ErrProviderNotFound   = errors.New("oauth provider not found")

	// Account errors
	ErrAccountNotFound         = errors.New("account not found")
	ErrCannotUnlinkLastAccount = errors.New("cannot unlink last account")
	ErrAccountAlreadyLinked    = errors.New("account already linked")

	// Verification errors
	ErrVerificationNotFound = errors.New("verification not found")
	ErrVerificationExpired  = errors.New("verification expired")
	ErrEmailNotVerified     = errors.New("email not verified")

	// Session errors
	ErrSessionNotFresh = errors.New("session not fresh, please re-authenticate")
)
