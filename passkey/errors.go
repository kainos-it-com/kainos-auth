package passkey

import "fmt"

// Errors
var (
	ErrInvalidChallenge = fmt.Errorf("invalid or expired challenge")
	ErrPasskeyNotFound  = fmt.Errorf("passkey not found")
	ErrInvalidSignature = fmt.Errorf("invalid signature")
	ErrCounterMismatch  = fmt.Errorf("counter mismatch - possible cloned authenticator")
	ErrNotImplemented   = fmt.Errorf("full WebAuthn verification not implemented")
)
