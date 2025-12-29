package ratelimit

import (
	"context"
	"sync"
	"time"
)

// MemoryStorage is an in-memory rate limit storage
type MemoryStorage struct {
	mu      sync.RWMutex
	entries map[string]*entry
}

type entry struct {
	count     int
	expiresAt time.Time
}

// NewMemoryStorage creates a new in-memory storage
func NewMemoryStorage() *MemoryStorage {
	s := &MemoryStorage{
		entries: make(map[string]*entry),
	}
	// Start cleanup goroutine
	go s.cleanup()
	return s
}

func (s *MemoryStorage) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	e, ok := s.entries[key]

	if !ok || now.After(e.expiresAt) {
		// Create new entry
		s.entries[key] = &entry{
			count:     1,
			expiresAt: now.Add(window),
		}
		return 1, nil
	}

	// Increment existing entry
	e.count++
	return e.count, nil
}

func (s *MemoryStorage) Get(ctx context.Context, key string) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return 0, nil
	}
	return e.count, nil
}

func (s *MemoryStorage) Reset(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}

func (s *MemoryStorage) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for key, e := range s.entries {
			if now.After(e.expiresAt) {
				delete(s.entries, key)
			}
		}
		s.mu.Unlock()
	}
}
