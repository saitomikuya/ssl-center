package auth

import (
	"sync"
	"time"
)

const (
	DefaultMaxAttempts = 5
	DefaultWindow      = 5 * time.Minute
	DefaultLockout     = 5 * time.Minute
)

type ipAttemptState struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	lastSeen    time.Time
}

// RateLimiter enforces per-IP brute-force protection for login requests.
type RateLimiter struct {
	mu          sync.Mutex
	maxAttempts int
	window      time.Duration
	lockout     time.Duration
	nowFn       func() time.Time
	entries     map[string]*ipAttemptState
	lastPrune   time.Time
}

// NewRateLimiter creates a per-IP rate limiter.
func NewRateLimiter(maxAttempts int, window, lockout time.Duration) *RateLimiter {
	if maxAttempts <= 0 {
		maxAttempts = DefaultMaxAttempts
	}
	if window <= 0 {
		window = DefaultWindow
	}
	if lockout <= 0 {
		lockout = DefaultLockout
	}
	now := time.Now().UTC()
	return &RateLimiter{
		maxAttempts: maxAttempts,
		window:      window,
		lockout:     lockout,
		nowFn:       func() time.Time { return time.Now().UTC() },
		entries:     make(map[string]*ipAttemptState),
		lastPrune:   now,
	}
}

// Allow checks if ip is allowed to attempt authentication. If blocked, returns
// allowed=false and the remaining lockout duration.
func (rl *RateLimiter) Allow(ip string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFn()
	rl.maybePruneLocked(now)

	st, ok := rl.entries[ip]
	if !ok {
		return true, 0
	}
	if !st.lockedUntil.IsZero() {
		if now.Before(st.lockedUntil) {
			return false, st.lockedUntil.Sub(now)
		}
		// Lockout expired; reset window.
		delete(rl.entries, ip)
		return true, 0
	}
	if now.Sub(st.windowStart) > rl.window {
		delete(rl.entries, ip)
		return true, 0
	}
	return true, 0
}

// RecordFailure records a failed login attempt for ip and returns whether the IP
// is now locked out along with the lockout duration.
func (rl *RateLimiter) RecordFailure(ip string) (bool, time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFn()
	rl.maybePruneLocked(now)

	st, ok := rl.entries[ip]
	if !ok || now.Sub(st.windowStart) > rl.window {
		st = &ipAttemptState{
			failures:    0,
			windowStart: now,
		}
		rl.entries[ip] = st
	}
	st.lastSeen = now

	if !st.lockedUntil.IsZero() && now.Before(st.lockedUntil) {
		return true, st.lockedUntil.Sub(now)
	}

	st.failures++
	if st.failures >= rl.maxAttempts {
		st.lockedUntil = now.Add(rl.lockout)
		return true, rl.lockout
	}
	return false, 0
}

// Reset clears failure tracking for ip after a successful login.
func (rl *RateLimiter) Reset(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.entries, ip)
}

func (rl *RateLimiter) maybePruneLocked(now time.Time) {
	if now.Sub(rl.lastPrune) < time.Minute && len(rl.entries) < 1024 {
		return
	}
	rl.lastPrune = now
	ttl := rl.window
	if rl.lockout > ttl {
		ttl = rl.lockout
	}
	for ip, st := range rl.entries {
		if !st.lockedUntil.IsZero() && now.After(st.lockedUntil) {
			delete(rl.entries, ip)
			continue
		}
		if st.lockedUntil.IsZero() && now.Sub(st.lastSeen) > ttl {
			delete(rl.entries, ip)
		}
	}
}
