package organization

import "time"

// Organization represents an organization
type Organization struct {
	ID        string
	Name      string
	Slug      string
	Logo      *string
	Metadata  map[string]interface{}
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Member represents an organization member
type Member struct {
	ID             string
	UserID         string
	OrganizationID string
	Role           string
	CreatedAt      time.Time
}

// Invitation represents an organization invitation
type Invitation struct {
	ID             string
	Email          string
	OrganizationID string
	InviterID      string
	Role           string
	Status         string // "pending", "accepted", "rejected", "cancelled"
	TeamID         *string
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

// Team represents a team within an organization
type Team struct {
	ID             string
	Name           string
	OrganizationID string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// TeamMember represents a team member
type TeamMember struct {
	ID        string
	TeamID    string
	UserID    string
	CreatedAt time.Time
}

// CreateInput contains data for creating an organization
type CreateInput struct {
	Name     string
	Slug     string
	Logo     *string
	Metadata map[string]interface{}
	UserID   string
}

// CreateResult contains the created organization and member
type CreateResult struct {
	Organization *Organization
	Member       *Member
}

// UpdateInput contains data for updating an organization
type UpdateInput struct {
	OrganizationID string
	Name           *string
	Slug           *string
	Logo           *string
	Metadata       map[string]interface{}
}

// InviteInput contains data for inviting a user
type InviteInput struct {
	Email          string
	OrganizationID string
	InviterID      string
	Role           string
	TeamID         *string
}
