package crawlgate

import (
	"net/http"
	"strings"
)

// RobotsTxt returns the robots.txt body the Gate serves. It guarantees a
// Disallow for the trap prefix (so compliant crawlers self-exclude) and, when
// RobotsExtra is set, merges it ahead of that rule.
func (g *Gate) RobotsTxt() string {
	trap := g.trapPrefix
	extra := strings.TrimSpace(g.cfg.RobotsExtra)
	if extra != "" {
		if !strings.Contains(extra, "Disallow: "+trap) {
			extra += "\n\n# added by crawlgate\nUser-agent: *\nDisallow: " + trap + "\n"
		}
		if !strings.HasSuffix(extra, "\n") {
			extra += "\n"
		}
		return extra
	}
	return "User-agent: *\nDisallow: " + trap + "\nAllow: /\n"
}

func (g *Gate) serveRobots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Crawlgate", "robots")
	_, _ = w.Write([]byte(g.RobotsTxt()))
}
