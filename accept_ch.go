package http

import (
	"slices"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/httpsfv"
)

// parseClientHintList parses the values of an Accept-CH or Critical-CH
// field, a structured field list of tokens (RFC 8941). It returns the
// lowercase names of the User-Agent client hints the list names, in order
// and without duplicates, and whether the field is valid. Names of other
// hints are skipped.
//
// A valid empty list returns nil and true; for Accept-CH it forgets what
// the origin asked for. Malformed syntax, or a member that is not a token,
// returns false, and the field is ignored.
func parseClientHintList(values []string) ([]string, bool) {
	value := strings.TrimSpace(strings.Join(values, ","))
	if value == "" {
		return nil, true
	}

	var hints []string

	tokens := true
	syntax := httpsfv.ParseList(value, func(member, _ string) {
		name, ok := httpsfv.ParseToken(member)
		if !ok {
			tokens = false

			return
		}

		name = strings.ToLower(name)
		if userAgentClientHint(name) && !slices.Contains(hints, name) {
			hints = append(hints, name)
		}
	})

	if !syntax || !tokens {
		return nil, false
	}

	return hints, true
}

// userAgentClientHint reports whether name, in lowercase, is a User-Agent
// client hint that a Chromium profile can send.
func userAgentClientHint(name string) bool {
	switch name {
	case "sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"sec-ch-ua-arch",
		"sec-ch-ua-bitness",
		"sec-ch-ua-platform-version",
		"sec-ch-ua-model",
		"sec-ch-ua-wow64",
		"sec-ch-ua-full-version",
		"sec-ch-ua-full-version-list",
		"sec-ch-ua-form-factors":
		return true
	default:
		return false
	}
}
