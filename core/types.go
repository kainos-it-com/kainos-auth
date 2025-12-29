package core

import (
	db "github.com/kainos.it.com/kainos-auth/db/sqlc"
)

// SignUpInput contains data for user registration
type SignUpInput struct {
	Name      string
	Email     string
	Password  string
	Image     *string
	IPAddress *string
	UserAgent *string
}

// SignInInput contains data for user login
type SignInInput struct {
	Email     string
	Password  string
	IPAddress *string
	UserAgent *string
}

// AuthResponse is returned after successful authentication
type AuthResponse struct {
	User    *db.User
	Session *db.Session
}

// OAuthCallbackInput contains OAuth callback data
type OAuthCallbackInput struct {
	Provider           string
	Code               string
	State              string
	IPAddress          *string
	UserAgent          *string
	LinkToExistingUser *string
}

// OAuthProfile represents a user profile from an OAuth provider
type OAuthProfile struct {
	ID            string
	Email         string
	Name          string
	Image         *string
	EmailVerified bool
	Raw           map[string]interface{}
}

// ChangePasswordInput contains data for password change
type ChangePasswordInput struct {
	UserID              string
	CurrentPassword     string
	NewPassword         string
	RevokeOtherSessions bool
	CurrentSessionID    string
}

// ResetPasswordInput contains data for password reset
type ResetPasswordInput struct {
	Email       string
	Token       string
	NewPassword string
}

// ChangeEmailInput contains data for email change
type ChangeEmailInput struct {
	UserID   string
	NewEmail string
	Token    string
}

// UpdateUserInput contains data for user update
type UpdateUserInput struct {
	UserID string
	Name   *string
	Image  *string
}

// DeleteUserInput contains data for user deletion
type DeleteUserInput struct {
	UserID   string
	Password *string
	Token    *string
}
