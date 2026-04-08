package auth

import (
	"log"
	"strings"
)

// LogFailedLogin emits a structured key=value log line for a failed
// login attempt. Format is deliberately simple key=value (not JSON)
// so it composes with Go's stdlib `log` without pulling in a
// structured logging dependency, and a downstream log aggregator
// can still parse it reliably with a single regex.
//
// Phase 5 Sprint 2 (S2) — added so a future SIEM layer has a
// structured join column (email) for cross-server failed-login
// correlation. The license server and report server each emit
// these independently today; a coordinator can merge them later.
//
// The event parameter lets callers distinguish the stage at which
// the failure occurred — "unknown_email", "bad_password",
// "rate_limited", "invite_expired", "role_mismatch" — so operators
// can tell an honest typo from a coordinated attack.
//
// email values are logged as-is because the caller already
// lowercased and trimmed them. IP comes from r.RemoteAddr via
// chi's RealIP middleware, which callers should pass directly.
// Any value containing whitespace or `"` is quoted; otherwise
// it's emitted bare for grep ergonomics.
func LogFailedLogin(server, event, email, ip, reason string) {
	log.Printf("event=login_failure server=%s stage=%s email=%s ip=%s reason=%s",
		kvValue(server), kvValue(event), kvValue(email), kvValue(ip), kvValue(reason))
}

// LogSuccessfulLogin emits the matching success event so operators
// can build per-email success/failure ratios for alerting. Kept
// separate from LogFailedLogin so each event has a fixed schema
// and grep filters on `event=login_success` vs `event=login_failure`
// stay trivial.
func LogSuccessfulLogin(server, email, ip string) {
	log.Printf("event=login_success server=%s email=%s ip=%s",
		kvValue(server), kvValue(email), kvValue(ip))
}

// kvValue formats a single value for key=value logging. Values
// containing whitespace, quotes, or `=` are double-quoted with
// embedded quotes escaped. Empty values become `-` so a parser
// can unambiguously distinguish "missing" from "empty-but-present".
func kvValue(s string) string {
	if s == "" {
		return "-"
	}
	if strings.ContainsAny(s, " \t\"=") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}
