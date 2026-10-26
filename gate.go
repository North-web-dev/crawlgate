package crawlgate

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/North-web-dev/crawlgate/ratelimit"
	"github.com/North-web-dev/crawlgate/tarpit"
	"github.com/North-web-dev/crawlgate/verify"
)

type action int

const (
	actionPass action = iota
	actionTarpit
	actionRateLimited
	actionDeny
	actionRobots
)

type decision struct {
	action     action
	reason     string
	res        verify.Result
	retryAfter time.Duration
}

// Gate is the middleware. Build it with New and install it with Wrap.
type Gate struct {
	cfg          Config
	verifier     *verify.Verifier
	limiter      *ratelimit.Limiter
	trapBudget   *ratelimit.Limiter
	maze         *tarpit.Maze
	verifiedOnly []string
	trapPrefix   string
}

// New builds a Gate from cfg. It returns an error if required fields are
// missing.
func New(cfg Config) (*Gate, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("crawlgate: Config.Verifier is required")
	}
	if cfg.TrapPath == "" {
		cfg.TrapPath = "/trap/"
	}
	if !strings.HasSuffix(cfg.TrapPath, "/") {
		cfg.TrapPath += "/"
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 5
	}
	if cfg.Burst <= 0 {
		cfg.Burst = 20
	}
	if cfg.MaxTrapPages <= 0 {
		cfg.MaxTrapPages = 50
	}
	if cfg.TrapWindow <= 0 {
		cfg.TrapWindow = 10 * time.Minute
	}
	g := &Gate{
		cfg:          cfg,
		verifier:     cfg.Verifier,
		limiter:      ratelimit.New(cfg.Rate, cfg.Burst, cfg.RateTTL, cfg.RateMax),
		trapBudget:   ratelimit.New(0, float64(cfg.MaxTrapPages), cfg.TrapWindow, cfg.RateMax),
		maze:         cfg.maze(),
		verifiedOnly: normPrefixes(cfg.VerifiedOnlyPaths),
		trapPrefix:   cfg.TrapPath,
	}
	return g, nil
}

// TrapPrefix returns the normalized honeypot path prefix.
func (g *Gate) TrapPrefix() string { return g.trapPrefix }

// Wrap installs the Gate in front of next (the upstream or application
// handler) and returns the resulting http.Handler.
func (g *Gate) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := g.classify(r)
		ip := g.clientIP(r)
		if g.cfg.Logger != nil {
			g.cfg.Logger.Printf("crawlgate ip=%s method=%s path=%s decision=%s verify=%s",
				ip, r.Method, redactPath(r.URL.Path), d.reason, d.res.Status)
		}
		if g.cfg.OnDecision != nil {
			g.cfg.OnDecision(ip, r.URL.Path, d.reason, d.res.Status)
		}

		switch d.action {
		case actionRobots:
			g.serveRobots(w, r)
		case actionDeny:
			w.Header().Set("X-Crawlgate", "deny")
			http.Error(w, "forbidden", http.StatusForbidden)
		case actionRateLimited:
			secs := int(d.retryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", itoa(secs))
			w.Header().Set("X-Crawlgate", "rate-limited")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
		case actionTarpit:
			g.serveTarpit(w, r, ip)
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func (g *Gate) classify(r *http.Request) decision {
	path := r.URL.Path
	if path == "/robots.txt" {
		return decision{action: actionRobots, reason: "robots"}
	}

	ip := g.clientIP(r)
	res := g.verifier.Verify(r.Context(), ip, r.UserAgent())

	// A verified good crawler is always allowed straight through.
	if res.Verified() {
		return decision{action: actionPass, reason: "verified:" + res.Bot, res: res}
	}

	if hasPrefix(path, g.verifiedOnly) {
		return decision{action: actionDeny, reason: "verified-only-path", res: res}
	}

	// Claiming a crawler and failing verification is a strong abuse signal.
	if res.Status == verify.StatusSpoofed {
		return decision{action: actionTarpit, reason: "spoofed-crawler:" + res.Bot, res: res}
	}

	// Honeypot: only clients ignoring robots.txt reach the trap prefix.
	if strings.HasPrefix(path, g.trapPrefix) {
		return decision{action: actionTarpit, reason: "trap-path", res: res}
	}

	botLike := g.botSignal(r)
	ok, retry := g.limiter.Allow(ip)
	if !ok {
		if botLike {
			return decision{action: actionTarpit, reason: "over-rate-automated", res: res}
		}
		return decision{action: actionRateLimited, reason: "over-rate", res: res, retryAfter: retry}
	}
	return decision{action: actionPass, reason: "pass", res: res}
}

func (g *Gate) botSignal(r *http.Request) bool {
	if uaLooksAutomated(r.UserAgent()) {
		return true
	}
	if g.cfg.BotFingerprint != nil {
		return g.cfg.BotFingerprint(r)
	}
	return false
}

func (g *Gate) serveTarpit(w http.ResponseWriter, r *http.Request, ip string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Crawlgate", "tarpit")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Cache-Control", "no-store")

	ok, _ := g.trapBudget.Allow(ip)
	var page []byte
	if ok {
		page = g.maze.Page(r.URL.Path)
	} else {
		// Budget exhausted for this IP: end the maze with a linkless leaf.
		page = g.maze.Leaf(r.URL.Path)
	}
	g.slowWrite(w, r, page)
}

// slowWrite streams page at the configured byte rate, honoring client
// disconnect, to waste an abusive scraper's time cheaply.
func (g *Gate) slowWrite(w http.ResponseWriter, r *http.Request, page []byte) {
	rate := g.cfg.TrapByteRate
	if rate <= 0 {
		_, _ = w.Write(page)
		return
	}
	flusher, _ := w.(http.Flusher)
	const tick = 100 * time.Millisecond
	chunk := rate / 10
	if chunk < 1 {
		chunk = 1
	}
	ctx := r.Context()
	for len(page) > 0 {
		n := chunk
		if n > len(page) {
			n = len(page)
		}
		if _, err := w.Write(page[:n]); err != nil {
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
		page = page[n:]
		if len(page) == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(tick):
		}
	}
}

func (g *Gate) clientIP(r *http.Request) string {
	if g.cfg.TrustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func normPrefixes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hasPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func redactPath(p string) string {
	// Paths carry no userinfo, but strip anything after a query delimiter so
	// credentials in query strings are never logged.
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

var automatedUATokens = []string{
	"bot", "crawl", "spider", "scraper", "scrapy", "python-requests",
	"python-urllib", "curl/", "wget/", "libwww", "httpclient", "okhttp",
	"java/", "go-http-client", "node-fetch", "axios", "headlesschrome",
	"phantomjs", "gptbot", "ccbot", "claudebot", "bytespider", "ahrefsbot",
	"semrushbot", "mj12bot", "dotbot", "petalbot", "dataforseo",
}

func uaLooksAutomated(ua string) bool {
	if ua == "" {
		return true // a well-behaved browser always sends a UA
	}
	l := strings.ToLower(ua)
	for _, t := range automatedUATokens {
		if strings.Contains(l, t) {
			return true
		}
	}
	return false
}
