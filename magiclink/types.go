package magiclink

import "time"

// SendInput contains data for sending a magic link
type SendInput struct {
	Email       string
	Name        string // Only used for new user registration
	CallbackURL string
	IPAddress   *string
	UserAgent   *string
}

// SendResult contains the result of sending a magic link
type SendResult struct {
	Token     string
	URL       string
	ExpiresAt time.Time
	IsNewUser bool
}

// VerifyInput contains data for verifying a magic link
type VerifyInput struct {
	Token     string
	Email     string
	IPAddress *string
	UserAgent *string
}
