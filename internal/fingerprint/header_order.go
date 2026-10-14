package fingerprint

import (
	"errors"
	"fmt"
	"net/textproto"
	"slices"

	"golang.org/x/net/http/httpguts"
)

// requestPseudoHeaders are the four pseudo-header fields of an ordinary
// HTTP/2 request.
var requestPseudoHeaders = []string{
	":method",
	":authority",
	":scheme",
	":path",
}

// ValidateHeaderOrder checks a header order list named field, such as
// "Profile.HeaderOrder". Names may use any case because ordering matches
// fields ignoring case, so two names that differ only in case are
// duplicates.
func ValidateHeaderOrder(field string, order []string) error {
	if len(order) == 0 {
		return nil
	}

	var problems []error
	seen := make(map[string]bool, len(order))

	for _, name := range order {
		if !httpguts.ValidHeaderFieldName(name) {
			problems = append(problems, fmt.Errorf("fphttp: %s contains invalid field name %q", field, name))

			continue
		}

		key := textproto.CanonicalMIMEHeaderKey(name)
		if seen[key] {
			problems = append(problems, fmt.Errorf("fphttp: %s lists %q more than once", field, key))
		}

		seen[key] = true
	}

	return errors.Join(problems...)
}

// ValidatePseudoHeaderOrder checks a pseudo-header order list named field.
// A non-empty order lists all four request pseudo-headers exactly once; an
// empty order selects the standard Go order.
func ValidatePseudoHeaderOrder(field string, order []string) error {
	if len(order) == 0 {
		return nil
	}

	var problems []error
	seen := make(map[string]bool, len(requestPseudoHeaders))

	for _, name := range order {
		switch {
		case !slices.Contains(requestPseudoHeaders, name):
			problems = append(problems, fmt.Errorf("fphttp: %s contains invalid pseudo-header %q", field, name))

		case seen[name]:
			problems = append(problems, fmt.Errorf("fphttp: %s lists %q more than once", field, name))
		}

		seen[name] = true
	}

	for _, name := range requestPseudoHeaders {
		if !seen[name] {
			problems = append(problems, fmt.Errorf("fphttp: %s is missing pseudo-header %q", field, name))
		}
	}

	return errors.Join(problems...)
}

// ResolveOrder returns the field order of one request: request when it is
// non-nil, even when empty, and otherwise fallback. It returns nil when the
// chosen order is empty, so an empty order from either source selects Go's
// order and writers only need to test for nil.
func ResolveOrder(request, fallback []string) []string {
	order := fallback
	if request != nil {
		order = request
	}

	if len(order) == 0 {
		return nil
	}

	return order
}
