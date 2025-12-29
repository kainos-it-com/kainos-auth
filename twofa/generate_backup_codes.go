package twofa

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// GenerateBackupCodes generates a set of backup codes
func (m *Manager) GenerateBackupCodes() ([]string, error) {
	codes := make([]string, m.config.BackupCodeCount)
	for i := 0; i < m.config.BackupCodeCount; i++ {
		code := make([]byte, 5)
		if _, err := rand.Read(code); err != nil {
			return nil, err
		}
		// Format: XXXX-XXXX (8 chars + hyphen)
		codes[i] = fmt.Sprintf("%04X-%04X",
			binary.BigEndian.Uint16(code[0:2]),
			binary.BigEndian.Uint16(code[2:4]))
	}
	return codes, nil
}
