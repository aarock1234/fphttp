package http

import (
	"crypto/tls"
	"fmt"
	"strings"
)

// validateTLSOwnership rejects TLSClientConfig fields that would change or
// bypass the ClientHello a profile owns. It names every conflicting field in
// one error. A profile without NewHello hands the handshake to crypto/tls,
// which honors those fields, so it conflicts with none of them.
func validateTLSOwnership(snapshot *Profile, config *tls.Config) error {
	if config == nil || snapshot.TLS.NewHello == nil {
		return nil
	}

	conflicts := tlsOwnershipConflicts(config)
	if len(conflicts) == 0 {
		return nil
	}

	verb := "conflict"
	if len(conflicts) == 1 {
		verb = "conflicts"
	}

	return fmt.Errorf(
		"fphttp: TLSClientConfig %s %s with Profile; edit Profile.TLS to change the ClientHello",
		joinFieldNames(conflicts),
		verb,
	)
}

// tlsOwnershipConflicts lists the TLSClientConfig fields that are set and
// belong to the profile's ClientHello, in the fixed order the conflict
// error names them: MinVersion, MaxVersion, CipherSuites, CurvePreferences,
// then ClientSessionCache.
func tlsOwnershipConflicts(config *tls.Config) []string {
	var conflicts []string

	if config.MinVersion != 0 {
		conflicts = append(conflicts, "MinVersion")
	}

	if config.MaxVersion != 0 {
		conflicts = append(conflicts, "MaxVersion")
	}

	if config.CipherSuites != nil {
		conflicts = append(conflicts, "CipherSuites")
	}

	if config.CurvePreferences != nil {
		conflicts = append(conflicts, "CurvePreferences")
	}

	if config.ClientSessionCache != nil {
		conflicts = append(conflicts, "ClientSessionCache")
	}

	return conflicts
}

// joinFieldNames joins names as an English list: "A", "A and B", or
// "A, B, and C".
func joinFieldNames(names []string) string {
	switch len(names) {
	case 0:
		return ""

	case 1:
		return names[0]

	case 2:
		return names[0] + " and " + names[1]

	default:
		last := len(names) - 1

		return strings.Join(names[:last], ", ") + ", and " + names[last]
	}
}
