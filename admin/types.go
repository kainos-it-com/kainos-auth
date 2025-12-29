package admin

import "time"

// CreateUserInput contains data for admin user creation
type CreateUserInput struct {
	Email    string
	Password string
	Name     string
	Role     string
	Data     map[string]interface{}
}

// ListUsersInput contains pagination and filter options
type ListUsersInput struct {
	Limit         int32
	Offset        int32
	SearchValue   string
	SearchField   string // "email" or "name"
	SortBy        string
	SortDirection string // "asc" or "desc"
	FilterField   string
	FilterValue   string
}

// BanUserInput contains data for banning a user
type BanUserInput struct {
	UserID       string
	BanReason    string
	BanExpiresIn *time.Duration
}
