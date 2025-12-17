package security

import (
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	buckets map[string]*bucket
	mutex   sync.RWMutex

	// Configuration
	maxRequests int           // Maximum requests per window
	window      time.Duration // Time window
	cleanup     time.Duration // Cleanup interval
}

// bucket represents a token bucket for a specific client
type bucket struct {
	tokens     int
	lastRefill time.Time
	mutex      sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		buckets:     make(map[string]*bucket),
		maxRequests: 100,             // 100 requests
		window:      time.Minute,     // per minute
		cleanup:     5 * time.Minute, // cleanup every 5 minutes
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given client should be allowed
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mutex.RLock()
	b, exists := rl.buckets[clientID]
	rl.mutex.RUnlock()

	if !exists {
		// Create new bucket for this client
		b = &bucket{
			tokens:     rl.maxRequests, // Start with full bucket
			lastRefill: time.Now(),
		}

		rl.mutex.Lock()
		rl.buckets[clientID] = b
		rl.mutex.Unlock()
	}

	return b.consume()
}

// consume attempts to consume a token from the bucket
func (b *bucket) consume() bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	now := time.Now()

	// Refill tokens based on time elapsed
	elapsed := now.Sub(b.lastRefill)
	if elapsed >= time.Minute {
		// Refill the bucket completely if a full minute has passed
		b.tokens = 100 // maxRequests
		b.lastRefill = now
	}

	// Try to consume a token
	if b.tokens > 0 {
		b.tokens--
		return true
	}

	return false
}

// cleanupLoop periodically removes old buckets
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanupOldBuckets()
	}
}

// cleanupOldBuckets removes buckets that haven't been used recently
func (rl *RateLimiter) cleanupOldBuckets() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-10 * time.Minute) // Remove buckets older than 10 minutes

	for clientID, bucket := range rl.buckets {
		bucket.mutex.Lock()
		if bucket.lastRefill.Before(cutoff) {
			delete(rl.buckets, clientID)
		}
		bucket.mutex.Unlock()
	}
}

// GetStats returns rate limiting statistics
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	return map[string]interface{}{
		"active_clients": len(rl.buckets),
		"max_requests":   rl.maxRequests,
		"window_seconds": int(rl.window.Seconds()),
	}
}

// SetLimits allows configuring the rate limits
func (rl *RateLimiter) SetLimits(maxRequests int, window time.Duration) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	rl.maxRequests = maxRequests
	rl.window = window

	// Clear existing buckets as limits have changed
	rl.buckets = make(map[string]*bucket)
}
