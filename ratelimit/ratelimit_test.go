package ratelimit

import (
	"testing"
	"time"
)

func TestTokenBucketBurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 3, time.Minute, 100) // 1 tok/s, burst 3
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("1.1.1.1"); !ok {
			t.Fatalf("request %d should be allowed (within burst)", i+1)
		}
	}
	ok, retry := l.Allow("1.1.1.1")
	if ok {
		t.Fatal("4th request should be denied")
	}
	if retry <= 0 {
		t.Fatalf("retryAfter should be positive, got %v", retry)
	}

	now = now.Add(1100 * time.Millisecond) // ~1 token refilled
	if ok, _ := l.Allow("1.1.1.1"); !ok {
		t.Fatal("after refill the request should be allowed")
	}
}

func TestIndependentKeys(t *testing.T) {
	l := New(1, 1, time.Minute, 100)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first key should pass")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("distinct key must have its own bucket")
	}
}

func TestLRUBoundsMemory(t *testing.T) {
	l := New(1, 1, time.Hour, 2) // cap 2 keys
	l.Allow("a")
	l.Allow("b")
	l.Allow("c")
	if got := l.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2 (LRU capped)", got)
	}
}

func TestTTLEviction(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(1, 1, time.Second, 100)
	l.now = func() time.Time { return now }
	l.Allow("a")
	now = now.Add(2 * time.Second)
	l.Allow("b") // triggers expiry sweep of "a"
	if got := l.Len(); got != 1 {
		t.Fatalf("Len = %d, want 1 (expired key evicted)", got)
	}
}
