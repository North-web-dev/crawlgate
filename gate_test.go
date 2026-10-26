package crawlgate

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/North-web-dev/crawlgate/verify"
)

type mockResolver struct {
	ptr map[string][]string
	fwd map[string][]net.IPAddr
}

func (m mockResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	n, ok := m.ptr[addr]
	if !ok {
		return nil, errors.New("no PTR")
	}
	return n, nil
}

func (m mockResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := m.fwd[host]
	if !ok {
		return nil, errors.New("NXDOMAIN")
	}
	return ips, nil
}

const (
	gbotIP  = "66.249.66.1"
	gbotUA  = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	humanUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
)

func testGate(t *testing.T, cfg Config) (*Gate, http.Handler, *bool) {
	t.Helper()
	res := mockResolver{
		ptr: map[string][]string{gbotIP: {"crawl-66-249-66-1.googlebot.com."}},
		fwd: map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {{IP: net.ParseIP(gbotIP)}}},
	}
	if cfg.Verifier == nil {
		cfg.Verifier = verify.New(verify.Options{Resolver: res})
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	upstreamHit := new(bool)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*upstreamHit = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("UPSTREAM"))
	})
	return g, g.Wrap(next), upstreamHit
}

func do(h http.Handler, method, target, ip, ua string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestVerifiedBotBypassesTarpit(t *testing.T) {
	_, h, hit := testGate(t, Config{TrapPath: "/trap/"})
	w := do(h, "GET", "/trap/anything", gbotIP, gbotUA)
	if !*hit {
		t.Fatalf("verified Googlebot must pass to upstream even on trap path; got %d / %q",
			w.Code, w.Header().Get("X-Crawlgate"))
	}
}

func TestSpoofedCrawlerTarpitted(t *testing.T) {
	_, h, hit := testGate(t, Config{})
	// 8.8.8.8 has no googlebot PTR in the mock -> spoof.
	w := do(h, "GET", "/", "8.8.8.8", gbotUA)
	if *hit {
		t.Fatal("spoofed Googlebot must not reach upstream")
	}
	if got := w.Header().Get("X-Crawlgate"); got != "tarpit" {
		t.Fatalf("X-Crawlgate = %q, want tarpit", got)
	}
}

func TestHumanOnTrapPathTarpitted(t *testing.T) {
	_, h, hit := testGate(t, Config{TrapPath: "/trap/"})
	w := do(h, "GET", "/trap/x", "203.0.113.5", humanUA)
	if *hit {
		t.Fatal("trap-path request must not reach upstream")
	}
	if w.Header().Get("X-Crawlgate") != "tarpit" {
		t.Fatalf("expected tarpit, got %q", w.Header().Get("X-Crawlgate"))
	}
	if !strings.Contains(w.Body.String(), "<html") {
		t.Fatal("tarpit must serve HTML")
	}
}

func TestHumanPassesThrough(t *testing.T) {
	_, h, hit := testGate(t, Config{})
	w := do(h, "GET", "/about", "203.0.113.6", humanUA)
	if !*hit {
		t.Fatalf("ordinary human traffic must fail open to upstream; got %d", w.Code)
	}
}

func TestRobotsDisallowsTrap(t *testing.T) {
	_, h, _ := testGate(t, Config{TrapPath: "/trap/"})
	w := do(h, "GET", "/robots.txt", "203.0.113.7", humanUA)
	body := w.Body.String()
	if !strings.Contains(body, "Disallow: /trap/") {
		t.Fatalf("robots.txt missing trap Disallow:\n%s", body)
	}
}

func TestRobotsMergeKeepsDisallow(t *testing.T) {
	_, h, _ := testGate(t, Config{TrapPath: "/trap/", RobotsExtra: "User-agent: *\nDisallow: /admin\n"})
	w := do(h, "GET", "/robots.txt", "203.0.113.8", humanUA)
	body := w.Body.String()
	if !strings.Contains(body, "Disallow: /admin") || !strings.Contains(body, "Disallow: /trap/") {
		t.Fatalf("merged robots.txt missing a rule:\n%s", body)
	}
}

func TestVerifiedOnlyPathDeniesNonVerified(t *testing.T) {
	_, h, hit := testGate(t, Config{VerifiedOnlyPaths: []string{"/premium"}})
	w := do(h, "GET", "/premium/data", "203.0.113.9", humanUA)
	if *hit {
		t.Fatal("non-verified client must not reach a verified-only path")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestVerifiedOnlyPathAllowsVerified(t *testing.T) {
	_, h, hit := testGate(t, Config{VerifiedOnlyPaths: []string{"/premium"}})
	w := do(h, "GET", "/premium/data", gbotIP, gbotUA)
	if !*hit {
		t.Fatalf("verified crawler must reach verified-only path; got %d", w.Code)
	}
}

func TestRateLimitHumanGets429(t *testing.T) {
	_, h, _ := testGate(t, Config{Rate: 1, Burst: 1})
	ip := "198.51.100.1"
	do(h, "GET", "/", ip, humanUA) // consumes the one token
	w := do(h, "GET", "/", ip, humanUA)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 must carry Retry-After")
	}
}

func TestRateLimitedBotGetsTarpit(t *testing.T) {
	_, h, _ := testGate(t, Config{Rate: 1, Burst: 1})
	ip := "198.51.100.2"
	botUA := "python-requests/2.31.0"
	do(h, "GET", "/", ip, botUA) // consumes token
	w := do(h, "GET", "/", ip, botUA)
	if got := w.Header().Get("X-Crawlgate"); got != "tarpit" {
		t.Fatalf("over-rate automated client: X-Crawlgate = %q, want tarpit (status %d)", got, w.Code)
	}
}

func TestBotFingerprintSignal(t *testing.T) {
	cfg := Config{Rate: 1, Burst: 1, BotFingerprint: func(_ *http.Request) bool { return true }}
	_, h, _ := testGate(t, cfg)
	ip := "198.51.100.3"
	do(h, "GET", "/", ip, humanUA) // browser UA, but fingerprint flags it
	w := do(h, "GET", "/", ip, humanUA)
	if w.Header().Get("X-Crawlgate") != "tarpit" {
		t.Fatalf("fingerprint-flagged over-rate client should be tarpitted, got %q", w.Header().Get("X-Crawlgate"))
	}
}
