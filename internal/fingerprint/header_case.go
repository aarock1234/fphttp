package fingerprint

import (
	"errors"
	"fmt"
	"net/textproto"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// ValidateHeaderCase permits spelling changes without renaming a field.
func ValidateHeaderCase(names map[string]string) error {
	var problems []error
	for name, spelling := range names {
		if !httpguts.ValidHeaderFieldName(name) || textproto.CanonicalMIMEHeaderKey(name) != name {
			problems = append(problems, fmt.Errorf("fphttp: H1HeaderCase key %q must be a canonical field name", name))
		}
		if !httpguts.ValidHeaderFieldName(spelling) || !strings.EqualFold(name, spelling) {
			problems = append(problems, fmt.Errorf("fphttp: H1HeaderCase value %q must spell %q with equivalent case", spelling, name))
		}
	}

	return errors.Join(problems...)
}
