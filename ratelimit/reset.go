package ratelimit

import (
	"context"
	"fmt"
)

// Reset resets the rate limit for a key
func (l *Limiter) Reset(ctx context.Context, key, endpoint string) error {
	compositeKey := fmt.Sprintf("%s:%s", endpoint, key)
	return l.storage.Reset(ctx, compositeKey)
}
