package http

import "fmt"

// CredentialsMode controls automatic cookie handling and whether a response
// may clear client hints through Clear-Site-Data. It does not change browser
// headers, caller-supplied Cookie or Authorization fields, URL user info, or
// TLS client certificates.
type CredentialsMode string

const (
	// CredentialsDefault preserves the credentials mode implied by Destination.
	CredentialsDefault CredentialsMode = ""

	// CredentialsInclude allows jar cookies for every request origin.
	CredentialsInclude CredentialsMode = "include"

	// CredentialsSameOrigin allows jar cookies only when Initiator is nil or
	// has the same origin as the current request URL.
	CredentialsSameOrigin CredentialsMode = "same-origin"

	// CredentialsOmit prevents sending and storing jar cookies and prevents
	// Clear-Site-Data from clearing client hints.
	CredentialsOmit CredentialsMode = "omit"
)

// validate rejects unknown credentials modes instead of silently changing
// whether a request carries cookies.
func (m CredentialsMode) validate() error {
	switch m {
	case CredentialsDefault, CredentialsInclude, CredentialsSameOrigin, CredentialsOmit:
		return nil
	default:
		return fmt.Errorf("fphttp: unknown request credentials mode %q", string(m))
	}
}

// credentialsMode returns the explicit mode or the existing destination
// default. It leaves the request's browser metadata unchanged.
func (r *Request) credentialsMode() CredentialsMode {
	if r.Credentials != CredentialsDefault {
		return r.Credentials
	}

	return r.Destination.credentials()
}
