package verify

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

type mockResolver struct {
	ptr map[string][]string     // ip -> PTR names
	fwd map[string][]net.IPAddr // host -> forward IPs
	err map[string]error        // ip -> LookupAddr error
}

func (m mockResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if e, ok := m.err[addr]; ok {
		return nil, e
	}
	names, ok := m.ptr[addr]
	if !ok {
		return nil, errors.New("no PTR")
	}
	return names, nil
}

func (m mockResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	ips, ok := m.fwd[host]
	if !ok {
		return nil, errors.New("NXDOMAIN")
	}
	return ips, nil
}

func ipaddr(s string) net.IPAddr { return net.IPAddr{IP: net.ParseIP(s)} }

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

func TestVerify(t *testing.T) {
	const gip = "66.249.66.1"
	tests := []struct {
		name string
		ip   string
		ua   string
		res  mockResolver
		want Status
	}{
		{
			name: "valid googlebot forward-confirmed",
			ip:   gip,
			ua:   googlebotUA,
			res: mockResolver{
				ptr: map[string][]string{gip: {"crawl-66-249-66-1.googlebot.com."}},
				fwd: map[string][]net.IPAddr{"crawl-66-249-66-1.googlebot.com": {ipaddr(gip)}},
			},
			want: StatusVerified,
		},
		{
			name: "spoofed wrong suffix",
			ip:   gip,
			ua:   googlebotUA,
			res: mockResolver{
				ptr: map[string][]string{gip: {"host.evil-example.com."}},
				fwd: map[string][]net.IPAddr{"host.evil-example.com": {ipaddr(gip)}},
			},
			want: StatusSpoofed,
		},
		{
			name: "spoofed suffix lookalike not dot-bounded",
			ip:   gip,
			ua:   googlebotUA,
			res: mockResolver{
				ptr: map[string][]string{gip: {"evilgooglebot.com."}},
				fwd: map[string][]net.IPAddr{"evilgooglebot.com": {ipaddr(gip)}},
			},
			want: StatusSpoofed,
		},
		{
			name: "spoofed forward-confirm mismatch",
			ip:   gip,
			ua:   googlebotUA,
			res: mockResolver{
				ptr: map[string][]string{gip: {"crawl-1.googlebot.com."}},
				fwd: map[string][]net.IPAddr{"crawl-1.googlebot.com": {ipaddr("8.8.8.8")}},
			},
			want: StatusSpoofed,
		},
		{
			name: "spoofed ptr lookup fails",
			ip:   gip,
			ua:   googlebotUA,
			res:  mockResolver{err: map[string]error{gip: errors.New("servfail")}},
			want: StatusSpoofed,
		},
		{
			name: "unknown no crawler claim",
			ip:   gip,
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
			res:  mockResolver{},
			want: StatusUnknown,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := New(Options{Resolver: tc.res})
			got := v.Verify(context.Background(), tc.ip, tc.ua)
			if got.Status != tc.want {
				t.Fatalf("status = %v (reason %q), want %v", got.Status, got.Reason, tc.want)
			}
		})
	}
}

func TestVerifyIPRangeFastPath(t *testing.T) {
	const gip = "66.249.66.7"
	ranges := map[string][]netip.Prefix{
		"Googlebot": {netip.MustParsePrefix("66.249.64.0/19")},
	}
	// Resolver would fail; the range alone must verify.
	v := New(Options{Resolver: mockResolver{}, IPRanges: ranges})
	got := v.Verify(context.Background(), gip, googlebotUA)
	if !got.Verified() {
		t.Fatalf("expected verified via ip-range, got %v (%q)", got.Status, got.Reason)
	}
	if got.Reason != "ip-range" {
		t.Fatalf("reason = %q, want ip-range", got.Reason)
	}
}

func TestVerifyCaches(t *testing.T) {
	const gip = "66.249.66.9"
	calls := 0
	countingPTR := map[string][]string{gip: {"crawl.googlebot.com."}}
	res := countingResolver{inner: mockResolver{
		ptr: countingPTR,
		fwd: map[string][]net.IPAddr{"crawl.googlebot.com": {ipaddr(gip)}},
	}, calls: &calls}
	v := New(Options{Resolver: res})
	for i := 0; i < 3; i++ {
		if !v.Verify(context.Background(), gip, googlebotUA).Verified() {
			t.Fatal("expected verified")
		}
	}
	if calls != 1 {
		t.Fatalf("LookupAddr called %d times, want 1 (cached)", calls)
	}
}

type countingResolver struct {
	inner mockResolver
	calls *int
}

func (c countingResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	*c.calls++
	return c.inner.LookupAddr(ctx, addr)
}

func (c countingResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return c.inner.LookupIPAddr(ctx, host)
}
