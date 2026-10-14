package http

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"golang.org/x/net/http/httpguts"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// validate checks the fields of p that a Transport cannot send as they are.
// It returns every problem joined with errors.Join. A nil TLS.NewHello is
// valid and selects crypto/tls.
func (p *Profile) validate() error {
	return errors.Join(
		validateProfileHeader(p.Header),
		fingerprint.ValidateHeaderOrder("Profile.HeaderOrder", p.HeaderOrder),
		fingerprint.ValidateHeaderOrder("Profile.SubresourceHeaderOrder", p.SubresourceHeaderOrder),
		fingerprint.ValidatePseudoHeaderOrder("Profile.PseudoHeaderOrder", p.PseudoHeaderOrder),
		fingerprint.ValidateHeaderCase("Profile.H1HeaderCase", p.H1HeaderCase),
		p.HTTP2.Validate(),
	)
}

// validateProfileHeader checks that every key of header is a valid field
// name and every value a valid field value, as the Transport later requires
// of each request. It reports the problems in sorted key order, so the
// error does not depend on map order. A present but empty value is valid:
// it suppresses the field.
func validateProfileHeader(header Header) error {
	var problems []error

	for _, name := range slices.Sorted(maps.Keys(header)) {
		if !httpguts.ValidHeaderFieldName(name) {
			problems = append(problems, fmt.Errorf("fphttp: Profile.Header contains invalid field name %q", name))

			continue
		}

		if !validFieldValues(header[name]) {
			problems = append(problems, fmt.Errorf("fphttp: Profile.Header contains invalid field value for %q", name))
		}
	}

	return errors.Join(problems...)
}

// validFieldValues reports whether every value in values is a valid field
// value.
func validFieldValues(values []string) bool {
	for _, value := range values {
		if !httpguts.ValidHeaderFieldValue(value) {
			return false
		}
	}

	return true
}
