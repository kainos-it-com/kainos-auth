package admin

import "fmt"

// Errors
var (
	ErrNotAuthorized          = fmt.Errorf("not authorized to perform this action")
	ErrCannotImpersonateAdmin = fmt.Errorf("cannot impersonate another admin")
	ErrUserBanned             = fmt.Errorf("user is banned")
)
