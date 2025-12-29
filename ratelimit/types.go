package ratelimit

import "time"

// Result contains rate limit check result
type Result struct {
	Allowed   bool
	Limit     int
	Remaining int
	ResetAt   time.Time
}
