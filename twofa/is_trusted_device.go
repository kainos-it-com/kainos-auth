package twofa

// IsTrustedDevice checks if a device is trusted for a user
func (m *Manager) IsTrustedDevice(userID, deviceID string) bool {
	// This would check the trusted_devices table
	// Implementation depends on store interface
	return false
}
