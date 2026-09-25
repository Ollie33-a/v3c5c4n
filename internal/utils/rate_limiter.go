package utils

import (
    "context"
    "time"
)

// RateLimiter limits operations to a specific rate
type RateLimiter struct {
    packetsPerSecond int
    ticker           *time.Ticker
    limiter          chan struct{}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(packetsPerSecond int) *RateLimiter {
    rl := &RateLimiter{
        packetsPerSecond: packetsPerSecond,
        limiter:          make(chan struct{}, packetsPerSecond),
    }

    // Pre-fill the channel
    for i := 0; i < packetsPerSecond; i++ {
        rl.limiter <- struct{}{}
    }

    // Refill at specified rate
    go rl.refill()

    return rl
}

// Wait blocks until a packet can be sent
func (rl *RateLimiter) Wait(ctx context.Context) error {
    select {
    case <-rl.limiter:
        return nil
    case <-ctx.Done():
        return ctx.Err()
    }
}

// refill refills the limiter
func (rl *RateLimiter) refill() {
    ticker := time.NewTicker(time.Second / time.Duration(rl.packetsPerSecond))
    defer ticker.Stop()

    for range ticker.C {
        select {
        case rl.limiter <- struct{}{}:
        default:
        }
    }
}

// Stop stops the rate limiter
func (rl *RateLimiter) Stop() {
    if rl.ticker != nil {
        rl.ticker.Stop()
    }
    close(rl.limiter)
}