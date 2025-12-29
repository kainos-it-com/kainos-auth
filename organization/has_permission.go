package organization

import "context"

// HasPermission checks if a user has a specific permission in an organization
func (m *Manager) HasPermission(ctx context.Context, userID, orgID, resource, action string) bool {
	member, err := m.GetMember(ctx, userID, orgID)
	if err != nil {
		return false
	}

	return checkRolePermission(member.Role, resource, action)
}

// checkRolePermission checks if a role has a specific permission
func checkRolePermission(role, resource, action string) bool {
	permissions := map[string]map[string][]string{
		"owner": {
			"organization": {"update", "delete"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
			"team":         {"create", "update", "delete"},
		},
		"admin": {
			"organization": {"update"},
			"member":       {"create", "update", "delete"},
			"invitation":   {"create", "cancel"},
			"team":         {"create", "update", "delete"},
		},
		"member": {
			// Members have read-only access by default
		},
	}

	rolePerms, ok := permissions[role]
	if !ok {
		return false
	}

	resourcePerms, ok := rolePerms[resource]
	if !ok {
		return false
	}

	for _, perm := range resourcePerms {
		if perm == action {
			return true
		}
	}

	return false
}
