package organization

import "time"

// Config holds organization configuration
type Config struct {
	AllowUserToCreateOrg bool
	OrganizationLimit    int // 0 = unlimited
	MembershipLimit      int
	CreatorRole          string
	InvitationExpiresIn  time.Duration
	InvitationLimit      int
	TeamsEnabled         bool
	MaxTeamsPerOrg       int
}

// DefaultConfig returns sensible organization defaults
func DefaultConfig() *Config {
	return &Config{
		AllowUserToCreateOrg: true,
		OrganizationLimit:    0,
		MembershipLimit:      100,
		CreatorRole:          "owner",
		InvitationExpiresIn:  48 * time.Hour,
		InvitationLimit:      100,
		TeamsEnabled:         false,
		MaxTeamsPerOrg:       0,
	}
}
