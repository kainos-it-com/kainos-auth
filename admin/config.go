package admin

import "time"

// Config holds admin configuration
type Config struct {
	AdminUserIDs             []string
	AdminRoles               []string
	DefaultRole              string
	ImpersonationDuration    time.Duration
	DefaultBanReason         string
	BannedUserMessage        string
	AllowImpersonatingAdmins bool
}

// DefaultConfig returns sensible admin defaults
func DefaultConfig() *Config {
	return &Config{
		AdminUserIDs:             []string{},
		AdminRoles:               []string{"admin"},
		DefaultRole:              "user",
		ImpersonationDuration:    1 * time.Hour,
		DefaultBanReason:         "No reason provided",
		BannedUserMessage:        "You have been banned. Please contact support.",
		AllowImpersonatingAdmins: false,
	}
}
