package store

import "errors"

var (
	ErrUserNotFound            = errors.New("user not found")
	ErrSessionNotFound         = errors.New("session not found")
	ErrSessionExpired          = errors.New("session expired")
	ErrAccountNotFound         = errors.New("account not found")
	ErrVerificationNotFound    = errors.New("verification not found")
	ErrVerificationExpired     = errors.New("verification expired")
	ErrInvalidToken            = errors.New("invalid token")
	ErrEmailAlreadyExists      = errors.New("email already exists")
	ErrCannotUnlinkLastAccount = errors.New("cannot unlink last account")
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrPasswordNotSet          = errors.New("password not set")
)
