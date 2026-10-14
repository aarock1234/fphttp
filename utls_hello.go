package http

import (
	"errors"
	"fmt"
	"reflect"

	utls "github.com/refraction-networking/utls"
)

// applyProfileHello builds a fresh ClientHello with newHello and applies it
// to conn.
func applyProfileHello(conn *utls.UConn, newHello func() (*utls.ClientHelloSpec, error)) error {
	spec, err := newProfileHello(newHello)
	if err != nil {
		return err
	}

	return conn.ApplyPreset(spec)
}

// newProfileHello calls newHello and checks that the spec it returns can be
// applied: it must be non-nil and pass validateClientHelloExtensions.
func newProfileHello(newHello func() (*utls.ClientHelloSpec, error)) (*utls.ClientHelloSpec, error) {
	spec, err := newHello()
	if err != nil {
		return nil, fmt.Errorf("NewHello: %w", err)
	}

	if spec == nil {
		return nil, errors.New("NewHello returned a nil spec")
	}

	if err := validateClientHelloExtensions(spec); err != nil {
		return nil, err
	}

	return spec, nil
}

// validateClientHelloExtensions rejects extension lists that make uTLS
// panic. NewHello is public, and uTLS reports these mistakes by panicking
// on the dialing goroutine, where no caller can recover, so they must
// become errors first:
//
//   - a nil extension, including a typed nil pointer, which uTLS would
//     dereference while marshaling;
//   - more than one session ticket extension;
//   - a pre_shared_key extension that is not the last extension, as
//     RFC 8446, Section 4.2.11 requires;
//   - a pre_shared_key extension other than *utls.UtlsPreSharedKeyExtension
//     (see validatePreSharedKeyExtension);
//   - a session ticket or pre_shared_key extension that already holds a
//     session.
//
// The last two only fail once a session is cached: resuming, uTLS
// initializes the session extensions from the Transport's session cache
// and panics when one cannot be initialized or already is. Checking every
// spec up front keeps a ClientHello that works on a first connection from
// crashing the process on a later, resumed one.
//
// The type switch classifies extensions in the order uTLS does when it
// syncs a spec's session extensions, so an extension counts as a session
// ticket or pre_shared_key extension exactly when uTLS treats it as one.
func validateClientHelloExtensions(spec *utls.ClientHelloSpec) error {
	last := len(spec.Extensions) - 1
	sessionTickets := 0

	for index, extension := range spec.Extensions {
		if isNilExtension(extension) {
			return fmt.Errorf("ClientHelloSpec.Extensions[%d] is nil", index)
		}

		switch extension := extension.(type) {
		case utls.ISessionTicketExtension:
			sessionTickets++

			if extension.IsInitialized() {
				return fmt.Errorf("ClientHelloSpec.Extensions[%d] is a session_ticket extension that already holds a session", index)
			}

		case utls.PreSharedKeyExtension:
			if err := validatePreSharedKeyExtension(extension, index == last); err != nil {
				return fmt.Errorf("ClientHelloSpec.Extensions[%d]: %w", index, err)
			}
		}
	}

	if sessionTickets > 1 {
		return fmt.Errorf("ClientHelloSpec.Extensions has %d session_ticket extensions, want at most one", sessionTickets)
	}

	return nil
}

// validatePreSharedKeyExtension checks a pre_shared_key extension; isLast
// reports whether it is the spec's last extension.
//
// Only *utls.UtlsPreSharedKeyExtension computes its identities and binders
// from a cached session, and uTLS panics when it resumes into any other
// type. FakePreSharedKeyExtension, which utls.Fingerprinter and the JSON
// spec loader produce unless RealPSKResumption or UseRealPSK is set, panics
// whether or not it carries identities. Every PreSharedKeyExtension embeds
// UnimplementedPreSharedKeyExtension, whose methods, IsInitialized among
// them, panic unless the type overrides them, so the type is checked before
// IsInitialized is called.
func validatePreSharedKeyExtension(extension utls.PreSharedKeyExtension, isLast bool) error {
	if !isLast {
		return errors.New("pre_shared_key must be the last extension")
	}

	psk, ok := extension.(*utls.UtlsPreSharedKeyExtension)
	if !ok {
		return fmt.Errorf("pre_shared_key extension is %T, want *utls.UtlsPreSharedKeyExtension", extension)
	}

	if psk.IsInitialized() {
		return errors.New("pre_shared_key extension already holds a session")
	}

	return nil
}

// isNilExtension reports whether extension is nil or a typed nil pointer.
func isNilExtension(extension utls.TLSExtension) bool {
	if extension == nil {
		return true
	}

	value := reflect.ValueOf(extension)

	return value.Kind() == reflect.Pointer && value.IsNil()
}
