// Package tarpit generates a bounded, deterministic labyrinth of synthetic
// HTML pages. It never fetches or echoes attacker-controlled content: every
// byte is generated locally from a seed and fully HTML-escaped. The maze is
// depth-bounded and size-capped so serving it costs the operator far less
// than crawling it costs an abusive scraper.
package tarpit

import (
	"encoding/binary"
	"hash/fnv"
	"html"
	"strings"
)

// Maze produces trap pages under a path prefix.
type Maze struct {
	Prefix       string // URL prefix for all trap pages, e.g. "/trap/"
	Seed         int64  // determinism seed; same seed+path => same page
	LinksPerPage int    // child links per non-leaf page (default 5)
	MaxDepth     int    // maximum link depth; beyond it, pages are leaves
	MaxBytes     int    // hard cap on generated page size (default 24 KiB)
}

// Normalize fills zero fields with safe defaults and returns the Maze.
func (m *Maze) Normalize() *Maze {
	if m.Prefix == "" {
		m.Prefix = "/trap/"
	}
	if !strings.HasSuffix(m.Prefix, "/") {
		m.Prefix += "/"
	}
	if m.LinksPerPage <= 0 {
		m.LinksPerPage = 5
	}
	if m.MaxDepth <= 0 {
		m.MaxDepth = 8
	}
	if m.MaxBytes <= 0 {
		m.MaxBytes = 24 * 1024
	}
	return m
}

// Depth returns how many path segments below the prefix reqPath sits at. The
// prefix root is depth 0.
func (m *Maze) Depth(reqPath string) int {
	rest := strings.TrimPrefix(reqPath, m.Prefix)
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return 0
	}
	return strings.Count(rest, "/") + 1
}

// Page renders the trap page for reqPath. The output is self-contained HTML,
// never larger than MaxBytes, and contains only escaped synthetic text. Links
// point to deeper trap paths until MaxDepth, after which the page is a leaf.
func (m *Maze) Page(reqPath string) []byte {
	return m.render(reqPath, false)
}

// Leaf renders a linkless trap page, used to terminate the maze for a client
// that has exhausted its per-IP page budget.
func (m *Maze) Leaf(reqPath string) []byte {
	return m.render(reqPath, true)
}

func (m *Maze) render(reqPath string, forceLeaf bool) []byte {
	m.Normalize()
	seed := m.pathSeed(reqPath)
	depth := m.Depth(reqPath)

	var b strings.Builder
	title := titleCase(words(seed, 2, 4))
	b.WriteString("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
	b.WriteString("<meta name=\"robots\" content=\"noindex,nofollow\">")
	b.WriteString("<title>")
	b.WriteString(html.EscapeString(title))
	b.WriteString("</title></head><body>\n")
	b.WriteString("<h1>")
	b.WriteString(html.EscapeString(title))
	b.WriteString("</h1>\n")

	paras := 2 + int(seed%3)
	for i := 0; i < paras; i++ {
		if b.Len() >= m.MaxBytes {
			break
		}
		b.WriteString("<p>")
		b.WriteString(html.EscapeString(sentence(seed+uint64(i)*2654435761, 12, 24)))
		b.WriteString("</p>\n")
	}

	if !forceLeaf && depth < m.MaxDepth {
		b.WriteString("<ul>\n")
		for i := 0; i < m.LinksPerPage; i++ {
			if b.Len() >= m.MaxBytes {
				break
			}
			childSeed := seed ^ (uint64(i+1) * 1099511628211)
			token := hexToken(childSeed)
			childPath := strings.TrimRight(reqPath, "/") + "/" + token
			b.WriteString("<li><a href=\"")
			b.WriteString(html.EscapeString(childPath))
			b.WriteString("\">")
			b.WriteString(html.EscapeString(titleCase(words(childSeed, 2, 3))))
			b.WriteString("</a></li>\n")
		}
		b.WriteString("</ul>\n")
	}
	b.WriteString("</body></html>\n")

	out := []byte(b.String())
	if len(out) > m.MaxBytes {
		out = out[:m.MaxBytes]
	}
	return out
}

// pathSeed derives a stable per-page seed from the maze seed and the path.
func (m *Maze) pathSeed(reqPath string) uint64 {
	h := fnv.New64a()
	var sb [8]byte
	binary.LittleEndian.PutUint64(sb[:], uint64(m.Seed))
	_, _ = h.Write(sb[:])
	_, _ = h.Write([]byte(reqPath))
	return h.Sum64()
}

// vocab is a fixed set of nonsense syllable-words. The content is synthetic by
// construction: it contains no real data and impersonates nothing.
var vocab = []string{
	"lorua", "venth", "qalis", "mordeck", "tavin", "greloth", "umber", "cindar",
	"polvex", "narrin", "zephal", "obrint", "yalmic", "druven", "crysa", "felmorn",
	"abstruse", "quandary", "lattice", "ferment", "solvent", "cadence", "vellum",
	"thistle", "harrow", "lumen", "praxis", "ravine", "solace", "tangent", "warren",
}

func rngNext(state *uint64) uint64 {
	// xorshift64* — deterministic, no allocations.
	x := *state
	if x == 0 {
		x = 0x9e3779b97f4a7c15
	}
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	*state = x
	return x * 0x2545f4914f6cdd1d
}

func words(seed uint64, min, max int) string {
	state := seed
	n := min + int(rngNext(&state)%uint64(max-min+1))
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = vocab[rngNext(&state)%uint64(len(vocab))]
	}
	return strings.Join(parts, " ")
}

func sentence(seed uint64, min, max int) string {
	s := words(seed, min, max)
	if s == "" {
		return s
	}
	return titleCase(s[:1]) + s[1:] + "."
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func hexToken(seed uint64) string {
	const hexd = "0123456789abcdef"
	state := seed
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		sb.WriteByte(hexd[rngNext(&state)%16])
	}
	return sb.String()
}
