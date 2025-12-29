package ratelimit

import "fmt"

// Errors
var (
	ErrRateLimitExceeded = fmt.Errorf("rate limit exceeded")
)
