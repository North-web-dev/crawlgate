// Package ratelimit provides a per-key token-bucket limiter with bounded
// memory: idle keys expire by TTL and the live set is capped with LRU
// eviction, so a flood of distinct source IPs cannot exhaust RAM.
package ratelimit

import (
	"container/list"
	"sync"
	"time"
)

// Limiter is a set of independent token buckets keyed by string (typically a
// client IP). It is safe for concurrent use.
type Limiter struct {
	rate  float64 // tokens added per second
	burst float64 // bucket capacity
	ttl   time.Duration
	max   int
	now   func() time.Time // injectable clock for tests

	mu    sync.Mutex
	items map[string]*list.Element
	lru   *list.List // front = most recently used
}

type entry struct {
	key    string
	tokens float64
	last   time.Time
}

// New returns a Limiter allowing rate tokens/second with the given burst
// capacity. Keys unused for ttl are evicted; at most max keys are retained.
func New(rate, burst float64, ttl time.Duration, max int) *Limiter {
	if burst <= 0 {
		burst = 1
	}
	if max <= 0 {
		max = 65536
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Limiter{
		rate:  rate,
		burst: burst,
		ttl:   ttl,
		max:   max,
		now:   time.Now,
		items: make(map[string]*list.Element),
		lru:   list.New(),
	}
}

// Allow consumes one token for key. It reports whether the request is within
// limit and, when not, how long until a token is available.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.evictExpired(now)

	el, exists := l.items[key]
	var e *entry
	if exists {
		e = el.Value.(*entry)
		e.tokens += now.Sub(e.last).Seconds() * l.rate
		if e.tokens > l.burst {
			e.tokens = l.burst
		}
		e.last = now
		l.lru.MoveToFront(el)
	} else {
		e = &entry{key: key, tokens: l.burst, last: now}
		l.items[key] = l.lru.PushFront(e)
		l.evictOverflow()
	}

	if e.tokens >= 1 {
		e.tokens--
		return true, 0
	}
	deficit := 1 - e.tokens
	if l.rate <= 0 {
		return false, time.Minute
	}
	return false, time.Duration(deficit / l.rate * float64(time.Second))
}

// Len reports the number of tracked keys (for tests and metrics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

func (l *Limiter) evictExpired(now time.Time) {
	for {
		back := l.lru.Back()
		if back == nil {
			return
		}
		e := back.Value.(*entry)
		if now.Sub(e.last) < l.ttl {
			return
		}
		l.lru.Remove(back)
		delete(l.items, e.key)
	}
}

func (l *Limiter) evictOverflow() {
	for len(l.items) > l.max {
		back := l.lru.Back()
		if back == nil {
			return
		}
		e := back.Value.(*entry)
		l.lru.Remove(back)
		delete(l.items, e.key)
	}
}
