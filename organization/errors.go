package organization

import "fmt"

// Errors
var (
	ErrOrgCreationDisabled = fmt.Errorf("organization creation is disabled")
	ErrOrgLimitReached     = fmt.Errorf("organization limit reached")
	ErrSlugTaken           = fmt.Errorf("organization slug is already taken")
	ErrNotAuthorized       = fmt.Errorf("not authorized to perform this action")
	ErrOwnerCannotLeave    = fmt.Errorf("owner cannot leave organization, transfer ownership first")
	ErrMemberNotFound      = fmt.Errorf("member not found")
	ErrInvitationNotFound  = fmt.Errorf("invitation not found")
	ErrInvitationExpired   = fmt.Errorf("invitation has expired")
	ErrAlreadyMember       = fmt.Errorf("user is already a member")
	ErrTeamsNotEnabled     = fmt.Errorf("teams feature is not enabled")
	ErrTeamLimitReached    = fmt.Errorf("team limit reached for this organization")
)
