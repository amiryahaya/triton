package credentials

import (
	"net"
	"sort"
	"testing"

	"github.com/google/uuid"

	"github.com/amiryahaya/triton/pkg/server/hostmatch"
)

func idSetEqual(a, b []uuid.UUID) bool {
	if len(a) != len(b) {
		return false
	}
	ac := make([]string, len(a))
	bc := make([]string, len(b))
	for i := range a {
		ac[i] = a[i].String()
		bc[i] = b[i].String()
	}
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func TestResolveMatcher_EmptyMatcher_MatchesAll(t *testing.T) {
	h1 := hostmatch.HostSummary{ID: uuid.New(), GroupID: uuid.New(), OS: "linux"}
	h2 := hostmatch.HostSummary{ID: uuid.New(), GroupID: uuid.New(), OS: "windows"}
	got := ResolveMatcher(Matcher{}, []hostmatch.HostSummary{h1, h2})
	if !idSetEqual(got, []uuid.UUID{h1.ID, h2.ID}) {
		t.Fatalf("empty matcher should return all hosts, got %v", got)
	}
}

func TestResolveMatcher_GroupFilter(t *testing.T) {
	g1, g2 := uuid.New(), uuid.New()
	h1 := hostmatch.HostSummary{ID: uuid.New(), GroupID: g1}
	h2 := hostmatch.HostSummary{ID: uuid.New(), GroupID: g2}
	h3 := hostmatch.HostSummary{ID: uuid.New(), GroupID: g1}
	got := ResolveMatcher(Matcher{GroupIDs: []uuid.UUID{g1}}, []hostmatch.HostSummary{h1, h2, h3})
	if !idSetEqual(got, []uuid.UUID{h1.ID, h3.ID}) {
		t.Fatalf("group filter mismatch: %v", got)
	}
}

func TestResolveMatcher_OSFilter(t *testing.T) {
	h1 := hostmatch.HostSummary{ID: uuid.New(), OS: "linux"}
	h2 := hostmatch.HostSummary{ID: uuid.New(), OS: "windows"}
	h3 := hostmatch.HostSummary{ID: uuid.New(), OS: "linux"}
	got := ResolveMatcher(Matcher{OS: "linux"}, []hostmatch.HostSummary{h1, h2, h3})
	if !idSetEqual(got, []uuid.UUID{h1.ID, h3.ID}) {
		t.Fatalf("os filter mismatch: %v", got)
	}
}

func TestResolveMatcher_CIDRFilter(t *testing.T) {
	h1 := hostmatch.HostSummary{ID: uuid.New(), Address: net.ParseIP("10.0.0.5")}
	h2 := hostmatch.HostSummary{ID: uuid.New(), Address: net.ParseIP("10.1.0.5")}
	h3 := hostmatch.HostSummary{ID: uuid.New(), Address: nil} // no address — excluded
	got := ResolveMatcher(Matcher{CIDR: "10.0.0.0/24"}, []hostmatch.HostSummary{h1, h2, h3})
	if !idSetEqual(got, []uuid.UUID{h1.ID}) {
		t.Fatalf("cidr filter mismatch: %v", got)
	}
}

func TestResolveMatcher_MultipleTagsAndSemantics(t *testing.T) {
	h1 := hostmatch.HostSummary{ID: uuid.New(), Tags: map[string]string{"env": "prod", "team": "sre"}}
	h2 := hostmatch.HostSummary{ID: uuid.New(), Tags: map[string]string{"env": "prod"}}
	h3 := hostmatch.HostSummary{ID: uuid.New(), Tags: map[string]string{"env": "prod", "team": "sre", "role": "db"}}
	got := ResolveMatcher(
		Matcher{Tags: map[string]string{"env": "prod", "team": "sre"}},
		[]hostmatch.HostSummary{h1, h2, h3},
	)
	if !idSetEqual(got, []uuid.UUID{h1.ID, h3.ID}) {
		t.Fatalf("tag-AND filter mismatch: %v", got)
	}
}

func TestResolveMatcher_InvalidCIDR_MatchesNothing(t *testing.T) {
	h1 := hostmatch.HostSummary{ID: uuid.New(), Address: net.ParseIP("10.0.0.5")}
	got := ResolveMatcher(Matcher{CIDR: "not-a-cidr"}, []hostmatch.HostSummary{h1})
	if len(got) != 0 {
		t.Fatalf("invalid cidr should return empty, got %v", got)
	}
}
