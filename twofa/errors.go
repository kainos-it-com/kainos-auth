package twofa

import "fmt"

// Errors
var (
	ErrTwoFactorNotEnabled = fmt.Errorf("two-factor authentication not enabled")
	ErrTwoFactorRequired   = fmt.Errorf("two-factor authentication required")
	ErrInvalidTOTPCode     = fmt.Errorf("invalid TOTP code")
	ErrInvalidBackupCode   = fmt.Errorf("invalid backup code")
	ErrBackupCodeUsed      = fmt.Errorf("backup code already used")
	ErrTwoFactorAlreadySet = fmt.Errorf("two-factor authentication already enabled")
	ErrOTPExpired          = fmt.Errorf("OTP code expired")
	ErrInvalidOTP          = fmt.Errorf("invalid OTP code")
)
