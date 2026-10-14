package http

import (
	"errors"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// validate checks the fields of p that a Transport cannot send as they are.
// It returns every problem joined with errors.Join. A nil TLS.NewHello is
// valid and selects crypto/tls.
func (p *Profile) validate() error {
	return errors.Join(
		fingerprint.ValidateHeaderOrder("Profile.HeaderOrder", p.HeaderOrder),
		fingerprint.ValidateHeaderOrder("Profile.SubresourceHeaderOrder", p.SubresourceHeaderOrder),
		fingerprint.ValidatePseudoHeaderOrder("Profile.PseudoHeaderOrder", p.PseudoHeaderOrder),
		fingerprint.ValidateHeaderCase("Profile.H1HeaderCase", p.H1HeaderCase),
		p.HTTP2.Validate(),
	)
}
