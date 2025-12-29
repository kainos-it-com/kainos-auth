package magiclink

import "fmt"

// Errors
var (
	ErrInvalidToken   = fmt.Errorf("invalid or expired magic link token")
	ErrTokenExpired   = fmt.Errorf("magic link token has expired")
	ErrSignUpDisabled = fmt.Errorf("sign up via magic link is disabled")
)
