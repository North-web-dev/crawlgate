// Package verify decides whether a client that claims to be a search-engine
// crawler (via its User-Agent) really is one, using forward-confirmed reverse
// DNS as the authoritative check and optional published IP ranges as a
// fast-path supplement.
package verify

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Status is the outcome of verifying one client.
type Status int

const (
	// StatusUnknown means the User-Agent did not claim to be any known
	// crawler. Such traffic is neither verified nor flagged by this package.
	StatusUnknown Status = iota
	// StatusVerified means the client claimed a known crawler and the claim
	// was confirmed (forward-confirmed rDNS, or a trusted IP range).
	StatusVerified
	// StatusSpoofed means the client claimed a known crawler but the claim
	// could not be confirmed. This is a strong abuse signal.
	StatusSpoofed
)

func (s Status) String() string {
	switch s {
	case StatusVerified:
		return "verified"
	case StatusSpoofed:
		return "spoofed"
	default:
		return "unknown"
	}
}

// Result is what Verify returns.
type Result struct {
	Status   Status
	Bot      string // name of the crawler claimed in the UA, if any
	Hostname string // confirmed PTR hostname when verified via rDNS
	Reason   string // short, log-friendly explanation
}

// Verified reports whether the client is a confirmed good crawler.
func (r Result) Verified() bool { return r.Status == StatusVerified }

// BotRule describes one crawler: how its User-Agent is recognised and which
// reverse-DNS hostname suffixes are considered authoritative for it.
type BotRule struct {
	Name     string
	UATokens []string // case-insensitive substrings that claim this bot
	Suffixes []string // valid rDNS hostname suffixes, e.g. ".googlebot.com"
}

// DefaultRules covers the major crawlers that operate forward-confirmable
// reverse DNS. Operators relying on crawlers that only publish IP ranges
// (for example DuckDuckBot) should supply those ranges via IPRanges.
func DefaultRules() []BotRule {
	return []BotRule{
		{Name: "Googlebot", UATokens: []string{"Googlebot", "Google-InspectionTool", "Storebot-Google", "GoogleOther", "APIs-Google", "AdsBot-Google", "Google-Extended"}, Suffixes: []string{".googlebot.com", ".google.com"}},
		{Name: "Bingbot", UATokens: []string{"bingbot", "BingPreview", "adidxbot", "MicrosoftPreview"}, Suffixes: []string{".search.msn.com"}},
		{Name: "Applebot", UATokens: []string{"Applebot"}, Suffixes: []string{".applebot.apple.com"}},
		{Name: "YandexBot", UATokens: []string{"YandexBot", "YandexImages", "YandexAccessibilityBot"}, Suffixes: []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
	}
}

// Resolver is the subset of net.Resolver that Verifier needs. *net.Resolver
// satisfies it; tests supply a mock.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Verifier performs forward-confirmed rDNS verification with a bounded,
// TTL'd result cache.
type Verifier struct {
	rules    []BotRule
	resolver Resolver
	ranges   map[string][]netip.Prefix // bot name -> trusted CIDRs
	ttl      time.Duration
	negTTL   time.Duration
	maxCache int

	mu    sync.Mutex
	cache map[string]cacheEntry // key: bot + "|" + ip
	order []string              // insertion order for bounded eviction
}

type cacheEntry struct {
	res Result
	exp time.Time
}

// Options configures a Verifier. The zero value yields safe defaults.
type Options struct {
	Rules    []BotRule                 // nil -> DefaultRules()
	Resolver Resolver                  // nil -> net.DefaultResolver
	IPRanges map[string][]netip.Prefix // optional trusted ranges per bot
	TTL      time.Duration             // positive-result cache TTL (default 1h)
	NegTTL   time.Duration             // spoof/negative cache TTL (default 5m)
	MaxCache int                       // cache entry cap (default 4096)
}

// New builds a Verifier.
func New(o Options) *Verifier {
	v := &Verifier{
		rules:    o.Rules,
		resolver: o.Resolver,
		ranges:   o.IPRanges,
		ttl:      o.TTL,
		negTTL:   o.NegTTL,
		maxCache: o.MaxCache,
		cache:    make(map[string]cacheEntry),
	}
	if v.rules == nil {
		v.rules = DefaultRules()
	}
	if v.resolver == nil {
		v.resolver = net.DefaultResolver
	}
	if v.ttl <= 0 {
		v.ttl = time.Hour
	}
	if v.negTTL <= 0 {
		v.negTTL = 5 * time.Minute
	}
	if v.maxCache <= 0 {
		v.maxCache = 4096
	}
	return v
}

// Verify classifies a client by its IP and claimed User-Agent. It performs
// network lookups only when the UA claims a known crawler.
func (v *Verifier) Verify(ctx context.Context, ip, userAgent string) Result {
	rule := v.matchUA(userAgent)
	if rule == nil {
		return Result{Status: StatusUnknown, Reason: "no-crawler-claim"}
	}
	addr, err := netip.ParseAddr(normalizeIP(ip))
	if err != nil {
		return Result{Status: StatusSpoofed, Bot: rule.Name, Reason: "unparseable-ip"}
	}

	key := rule.Name + "|" + addr.String()
	if r, ok := v.cacheGet(key); ok {
		return r
	}

	res := v.verifyUncached(ctx, addr, *rule)
	ttl := v.ttl
	if res.Status != StatusVerified {
		ttl = v.negTTL
	}
	v.cachePut(key, res, ttl)
	return res
}

func (v *Verifier) verifyUncached(ctx context.Context, addr netip.Addr, rule BotRule) Result {
	// Fast-path: a trusted published range short-circuits to verified. rDNS
	// remains authoritative; ranges are an offline supplement.
	for _, p := range v.ranges[rule.Name] {
		if p.Contains(addr) {
			return Result{Status: StatusVerified, Bot: rule.Name, Reason: "ip-range"}
		}
	}

	names, err := v.resolver.LookupAddr(ctx, addr.String())
	if err != nil || len(names) == 0 {
		return Result{Status: StatusSpoofed, Bot: rule.Name, Reason: "ptr-lookup-failed"}
	}

	for _, name := range names {
		host := strings.ToLower(strings.TrimSuffix(name, "."))
		if !hasAllowedSuffix(host, rule.Suffixes) {
			continue
		}
		// Forward-confirm: the PTR hostname must resolve back to this IP. A
		// raw PTR is attacker-influenceable; this step makes it authoritative.
		ips, ferr := v.resolver.LookupIPAddr(ctx, host)
		if ferr != nil {
			continue
		}
		for _, ipa := range ips {
			if a, ok := netip.AddrFromSlice(ipa.IP); ok && a.Unmap() == addr.Unmap() {
				return Result{Status: StatusVerified, Bot: rule.Name, Hostname: host, Reason: "forward-confirmed-rdns"}
			}
		}
	}
	return Result{Status: StatusSpoofed, Bot: rule.Name, Reason: "forward-confirm-failed"}
}

func (v *Verifier) matchUA(ua string) *BotRule {
	for i := range v.rules {
		for _, tok := range v.rules[i].UATokens {
			if tok != "" && strings.Contains(ua, tok) {
				return &v.rules[i]
			}
		}
	}
	return nil
}

func hasAllowedSuffix(host string, suffixes []string) bool {
	for _, s := range suffixes {
		s = strings.ToLower(s)
		// Require a dot-bounded suffix so "evilgooglebot.com" never matches
		// ".googlebot.com".
		if host == strings.TrimPrefix(s, ".") || strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

func normalizeIP(ip string) string {
	if h, _, err := net.SplitHostPort(ip); err == nil {
		return h
	}
	return ip
}

func (v *Verifier) cacheGet(key string) (Result, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.cache[key]
	if !ok {
		return Result{}, false
	}
	if time.Now().After(e.exp) {
		delete(v.cache, key)
		return Result{}, false
	}
	return e.res, true
}

func (v *Verifier) cachePut(key string, res Result, ttl time.Duration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, exists := v.cache[key]; !exists {
		v.order = append(v.order, key)
	}
	v.cache[key] = cacheEntry{res: res, exp: time.Now().Add(ttl)}
	for len(v.cache) > v.maxCache && len(v.order) > 0 {
		oldest := v.order[0]
		v.order = v.order[1:]
		delete(v.cache, oldest)
	}
}

// ParsePrefixes turns a list of CIDR strings into netip.Prefix values,
// skipping blanks. It is a helper for loading IP-range config.
func ParsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
