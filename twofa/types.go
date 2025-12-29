package twofa

import "time"

// TwoFactorData represents stored 2FA data for a user
type TwoFactorData struct {
	ID          string
	UserID      string
	Secret      string
	BackupCodes string // JSON array of hashed codes
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// EnableInput contains data for enabling 2FA
type EnableInput struct {
	UserID   string
	Password string
}

// EnableResult contains the result of enabling 2FA
type EnableResult struct {
	Secret  string
	URI     string
	QRCode  string // base64 encoded QR code data URL
	Enabled bool
}

// VerifyInput contains data for verifying 2FA
type VerifyInput struct {
	UserID      string
	Code        string
	TrustDevice bool
	DeviceID    string
	IPAddress   string
	UserAgent   string
}

// OTPInput contains data for OTP operations
type OTPInput struct {
	UserID string
	Email  string
	Type   string // "email" or "sms"
}

// OTPResult contains the generated OTP
type OTPResult struct {
	Code      string
	ExpiresAt time.Time
}

// TrustedDevice represents a trusted device
type TrustedDevice struct {
	ID        string
	UserID    string
	DeviceID  string
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}
