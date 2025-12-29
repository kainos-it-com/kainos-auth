package ratelimit

import (
	"context"
	"time"
)

// Storage interface for rate limit data
type Storage interface {
	// Increment increments the counter and returns the new count
	Increment(ctx context.Context, key string, window time.Duration) (int, error)
	// Get returns the current count
	Get(ctx context.Context, key string) (int, error)
	// Reset resets the counter
	Reset(ctx context.Context, key string) error
}
