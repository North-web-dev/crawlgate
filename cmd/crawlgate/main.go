// Command crawlgate is a defensive reverse proxy: it verifies real search
// crawlers, rate-limits everyone else, and tarpits unverified abusive bots
// that ignore robots.txt. Run it in front of an upstream HTTP service.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/North-web-dev/crawlgate"
	"github.com/North-web-dev/crawlgate/verify"
	guard "github.com/North-web-dev/ja4-guard/guard"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	if err := run(); err != nil {
		log.Fatalf("crawlgate: %v", err)
	}
}

func run() error {
	fs := flag.NewFlagSet("crawlgate", flag.ContinueOnError)
	var (
		addr        = fs.String("addr", "127.0.0.1:8080", "listen address (non-loopback requires -allow-public)")
		upstream    = fs.String("upstream", "", "upstream base URL to proxy to, e.g. http://127.0.0.1:9000 (required)")
		trapPath    = fs.String("trap-path", "/trap/", "robots-disallowed honeypot path prefix")
		rate        = fs.Float64("rate", 5, "per-IP token-bucket rate (requests/second) for non-verified clients")
		burst       = fs.Float64("burst", 20, "per-IP token-bucket burst capacity")
		verOnly     = fs.String("verified-only-paths", "", "comma-separated path prefixes only verified crawlers may hit")
		ipRanges    = fs.String("ipranges", "", "JSON file of trusted crawler IP ranges: {\"Googlebot\":[\"66.249.64.0/19\"]}")
		useJA4      = fs.Bool("ja4", false, "use JA4 TLS fingerprinting as an extra bot signal (requires -tls-cert/-tls-key)")
		maxTrap     = fs.Int("max-trap-pages", 50, "max trap pages served to one IP per 10m window")
		trapByte    = fs.Int("trap-byte-rate", 0, "throttle trap output to N bytes/second (0 = unthrottled)")
		seed        = fs.Int64("seed", 1, "seed for deterministic trap content")
		trustFwd    = fs.Bool("trust-forwarded", false, "read client IP from X-Forwarded-For (only behind a trusted proxy)")
		robotsFile  = fs.String("robots-file", "", "optional robots.txt to merge; the trap-path Disallow is always ensured")
		allowPublic = fs.Bool("allow-public", false, "permit binding a non-loopback address")
		tlsCert     = fs.String("tls-cert", "", "TLS certificate file (enables HTTPS)")
		tlsKey      = fs.String("tls-key", "", "TLS key file")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *upstream == "" {
		fs.Usage()
		return fmt.Errorf("-upstream is required")
	}
	upURL, err := url.Parse(*upstream)
	if err != nil || upURL.Scheme == "" || upURL.Host == "" {
		return fmt.Errorf("invalid -upstream %q", *upstream)
	}
	if err := checkBind(*addr, *allowPublic); err != nil {
		return err
	}
	tlsEnabled := *tlsCert != "" && *tlsKey != ""
	if *useJA4 && !tlsEnabled {
		return fmt.Errorf("-ja4 requires -tls-cert and -tls-key (JA4 is read from the TLS ClientHello)")
	}

	ranges, err := loadRanges(*ipRanges)
	if err != nil {
		return fmt.Errorf("loading -ipranges: %w", err)
	}

	vf := verify.New(verify.Options{IPRanges: ranges})

	cfg := crawlgate.Config{
		TrapPath:          *trapPath,
		VerifiedOnlyPaths: splitComma(*verOnly),
		Rate:              *rate,
		Burst:             *burst,
		MaxTrapPages:      *maxTrap,
		TrapByteRate:      *trapByte,
		Seed:              *seed,
		TrustForwarded:    *trustFwd,
		RobotsExtra:       readFileOpt(*robotsFile),
		Verifier:          vf,
		Logger:            log.Default(),
	}
	if *useJA4 {
		cfg.BotFingerprint = ja4BotSignal()
		log.Printf("JA4 signal enabled: non-browser fingerprints feed the classifier (TLS is terminated here; L4 SNI passthrough is unsupported)")
	}

	gate, err := crawlgate.New(cfg)
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(upURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
		log.Printf("upstream error: %v", e)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}
	handler := gate.Wrap(proxy)

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	log.Printf("crawlgate listening on %s -> %s (trap=%s rate=%.1f/s tls=%t ja4=%t)",
		*addr, upURL, gate.TrapPrefix(), *rate, tlsEnabled, *useJA4)

	if tlsEnabled {
		cert, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if err != nil {
			return err
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if *useJA4 {
			srv.ConnContext = guard.ConnContext
			return srv.Serve(guard.NewListener(ln, tlsCfg))
		}
		return srv.Serve(tls.NewListener(ln, tlsCfg))
	}
	return srv.Serve(ln)
}

// ja4BotSignal returns a BotFingerprint that flags any TLS client whose JA4 is
// not a recognised browser. It relies on ja4-guard's embedded known-browser
// allow-list; unknown or missing fingerprints are treated as a bot signal
// only, never a hard block.
func ja4BotSignal() func(*http.Request) bool {
	browserPolicy := guard.KnownBrowserPolicy()
	return func(r *http.Request) bool {
		fp, ok := guard.FromRequest(r)
		if !ok || fp.JA4 == "" {
			return false
		}
		return !browserPolicy.Evaluate(fp.JA4).Allow
	}
}

func checkBind(addr string, allowPublic bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid -addr %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("-addr %q binds all interfaces; pass -allow-public to confirm", addr)
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	if !allowPublic {
		return fmt.Errorf("-addr %q is not loopback; pass -allow-public to bind it deliberately", addr)
	}
	log.Printf("WARNING: binding non-loopback address %s; ensure this exposure is intended", addr)
	return nil
}

func loadRanges(path string) (map[string][]netip.Prefix, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	out := make(map[string][]netip.Prefix, len(raw))
	for bot, cidrs := range raw {
		p, err := verify.ParsePrefixes(cidrs)
		if err != nil {
			return nil, fmt.Errorf("bot %q: %w", bot, err)
		}
		out[bot] = p
	}
	return out, nil
}

func splitComma(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func readFileOpt(path string) string {
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("WARNING: cannot read -robots-file %q: %v", path, err)
		return ""
	}
	return string(data)
}
