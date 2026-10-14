package fingerprint

import (
	"errors"
	"fmt"
	"maps"
	"net/textproto"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// ValidateHeaderCase checks an HTTP/1.1 casing map named field, such as
// "Profile.H1HeaderCase". A key names a field in any case and is matched
// ignoring case, so two keys that differ only in case are duplicates. Each
// value must spell its key with different case only, never a different
// name. Problems are reported in key order.
func ValidateHeaderCase(field string, names map[string]string) error {
	if len(names) == 0 {
		return nil
	}

	var problems []error
	seen := make(map[string]bool, len(names))

	for _, name := range slices.Sorted(maps.Keys(names)) {
		spelling := names[name]

		if !httpguts.ValidHeaderFieldName(name) {
			problems = append(problems, fmt.Errorf("fphttp: %s key %q is not a valid field name", field, name))

			continue
		}

		key := textproto.CanonicalMIMEHeaderKey(name)
		if seen[key] {
			problems = append(problems, fmt.Errorf("fphttp: %s lists %q more than once", field, key))
		}

		seen[key] = true

		if !httpguts.ValidHeaderFieldName(spelling) || !strings.EqualFold(name, spelling) {
			problems = append(problems, fmt.Errorf("fphttp: %s value %q must spell %q with different case only", field, spelling, name))
		}
	}

	return errors.Join(problems...)
}
