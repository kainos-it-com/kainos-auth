package twofa

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ValidateTOTP validates a TOTP code against a secret
// Accepts codes from one period before and after current time
func (m *Manager) ValidateTOTP(secret, code string) bool {
	now := time.Now().Unix()
	period := int64(m.config.TOTPPeriod)

	// Check current, previous, and next time windows
	for _, offset := range []int64{-1, 0, 1} {
		counter := (now / period) + offset
		expected := m.generateTOTPCode(secret, counter)
		if expected == code {
			return true
		}
	}
	return false
}

// generateTOTPCode generates a TOTP code for a given counter
func (m *Manager) generateTOTPCode(secret string, counter int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff

	code := truncated % 1000000
	return fmt.Sprintf("%06d", code)
}
