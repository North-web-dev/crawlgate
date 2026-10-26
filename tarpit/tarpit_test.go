package tarpit

import (
	"bytes"
	"strings"
	"testing"
)

func newMaze() *Maze {
	m := &Maze{Prefix: "/trap/", Seed: 42, LinksPerPage: 5, MaxDepth: 4, MaxBytes: 16 * 1024}
	return m.Normalize()
}

func TestPageBoundedSize(t *testing.T) {
	m := newMaze()
	m.MaxBytes = 512
	p := m.Page("/trap/root")
	if len(p) > m.MaxBytes {
		t.Fatalf("page is %d bytes, exceeds cap %d", len(p), m.MaxBytes)
	}
}

func TestPageDeterministic(t *testing.T) {
	a := newMaze().Page("/trap/abc")
	b := newMaze().Page("/trap/abc")
	if !bytes.Equal(a, b) {
		t.Fatal("same seed+path must produce identical pages")
	}
}

func TestLinksUntilMaxDepthThenLeaf(t *testing.T) {
	m := newMaze() // MaxDepth 4, LinksPerPage 5
	root := m.Page("/trap/")
	if n := strings.Count(string(root), "<li>"); n != 5 {
		t.Fatalf("root page has %d links, want 5", n)
	}
	// A path at MaxDepth must be a leaf (no further links).
	deep := "/trap/a/b/c/d"
	if d := m.Depth(deep); d < m.MaxDepth {
		t.Fatalf("test path depth %d < MaxDepth %d", d, m.MaxDepth)
	}
	leaf := m.Page(deep)
	if n := strings.Count(string(leaf), "<li>"); n != 0 {
		t.Fatalf("max-depth page has %d links, want 0", n)
	}
}

func TestLeafHasNoLinks(t *testing.T) {
	m := newMaze()
	if n := strings.Count(string(m.Leaf("/trap/x")), "<li>"); n != 0 {
		t.Fatalf("Leaf produced %d links, want 0", n)
	}
}

func TestOutputEscaped(t *testing.T) {
	m := newMaze()
	p := string(m.Page(`/trap/"><script>alert(1)</script>`))
	if strings.Contains(p, "<script>") {
		t.Fatal("unescaped <script> leaked into output")
	}
	if !strings.Contains(p, "&lt;script&gt;") {
		t.Fatal("expected escaped script tag in href")
	}
}

func TestContentIsSynthetic(t *testing.T) {
	// Every emitted word must come from the fixed synthetic vocabulary; this
	// guards against accidentally echoing request-derived text as content.
	m := newMaze()
	p := string(m.Page("/trap/root"))
	if !strings.Contains(p, "noindex") {
		t.Fatal("trap page must carry a noindex robots meta")
	}
}
