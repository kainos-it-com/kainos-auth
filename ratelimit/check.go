package ratelimit

import (
	"context"
	"fmt"
	"time"
)

// Check checks if a request is allowed
func (l *Limiter) Check(ctx context.Context, key, endpoint string) (*Result, error) {
	limit := l.config.DefaultLimit
	window := l.config.DefaultWindow

	// Check for endpoint-specific limits
	if endpointLimit, ok := l.config.EndpointLimits[endpoint]; ok {
		limit = endpointLimit.Limit
		window = endpointLimit.Window
	}

	// Create composite key
	compositeKey := fmt.Sprintf("%s:%s", endpoint, key)

	// Increment counter
	count, err := l.storage.Increment(ctx, compositeKey, window)
	if err != nil {
		return nil, err
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:   count <= limit,
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   time.Now().Add(window),
	}, nil
}
