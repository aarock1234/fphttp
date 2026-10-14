package http

import (
	"errors"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// validateRequestOrder checks a request's own order, casing, and priority
// fields. They change per request, so every request is checked. It returns
// every problem joined with errors.Join.
func validateRequestOrder(request *Request) error {
	var priorityErr error
	if request.H2Priority != nil {
		priorityErr = request.H2Priority.Validate(0)
	}

	return errors.Join(
		priorityErr,
		fingerprint.ValidateHeaderOrder("Request.HeaderOrder", request.HeaderOrder),
		fingerprint.ValidateHeaderCase("Request.H1HeaderCase", request.H1HeaderCase),
		fingerprint.ValidatePseudoHeaderOrder("Request.PseudoHeaderOrder", request.PseudoHeaderOrder),
	)
}
