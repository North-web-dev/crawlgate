// Package crawlgate is defensive bot management for Go HTTP servers: it
// verifies legitimate search crawlers with forward-confirmed reverse DNS,
// rate-limits everyone else, and feeds unverified abusive crawlers a cheap,
// non-destructive tarpit. It works as net/http middleware or, via cmd/crawlgate,
// as a reverse proxy in front of an existing site.
//
// The design is deliberately fail-open for humans: ordinary unknown traffic is
// passed through untouched. Only clients that spoof a crawler, ignore the
// robots-disallowed trap paths, or exceed the rate limit while looking
// automated are ever diverted.
package crawlgate

import (
	"log"
	"net/http"
	"time"

	"github.com/North-web-dev/crawlgate/tarpit"
	"github.com/North-web-dev/crawlgate/verify"
)

// Config configures a Gate. The zero value is not usable; use sensible values
// or the cmd defaults.
type Config struct {
	// TrapPath is the robots-disallowed honeypot prefix. Requests under it
	// from non-verified clients receive the tarpit. Default "/trap/".
	TrapPath string

	// VerifiedOnlyPaths are path prefixes only verified crawlers may reach.
	// Non-verified requests to them get 403.
	VerifiedOnlyPaths []string

	// Rate and Burst configure the per-IP token bucket (tokens/second and
	// bucket capacity) applied to non-verified clients.
	Rate  float64
	Burst float64

	// RateTTL and RateMax bound limiter memory.
	RateTTL time.Duration
	RateMax int

	// MaxTrapPages caps trap pages served to one IP per TrapWindow; beyond it
	// the maze ends in a leaf. TrapByteRate throttles trap output (bytes/sec,
	// 0 = unthrottled).
	MaxTrapPages int
	TrapWindow   time.Duration
	TrapByteRate int

	// Seed makes trap content deterministic.
	Seed int64

	// TrustForwarded makes the Gate read the client IP from X-Forwarded-For.
	// Enable ONLY behind a trusted proxy that sets it; it is spoofable.
	TrustForwarded bool

	// RobotsExtra, if set, is served (merged) as the body of /robots.txt with
	// the trap-path Disallow appended. When empty a minimal robots.txt is
	// generated.
	RobotsExtra string

	// Verifier performs crawler verification. Required.
	Verifier *verify.Verifier

	// BotFingerprint, if set, returns true when a request's transport
	// fingerprint (e.g. JA4) looks non-browser. It is an optional extra bot
	// signal; it never overrides crawler verification.
	BotFingerprint func(r *http.Request) bool

	// Logger receives one line per decision when non-nil.
	Logger *log.Logger

	// OnDecision, if set, is invoked for every request with its outcome.
	OnDecision func(ip, path, reason string, status verify.Status)
}

func (c *Config) maze() *tarpit.Maze {
	m := &tarpit.Maze{Prefix: c.TrapPath, Seed: c.Seed}
	return m.Normalize()
}
