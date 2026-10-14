package browser

import (
	"slices"

	http "github.com/aarock1234/fphttp/v2"
)

// Profile is an immutable selection. Returned metadata and fingerprint slices
// are independently owned; spec factories construct fresh handshake state.
type Profile struct {
	descriptor  Descriptor
	fingerprint *http.Fingerprint
}

// Descriptor returns an independently owned snapshot of the profile metadata.
func (p *Profile) Descriptor() Descriptor {
	if p == nil {
		return Descriptor{}
	}

	return cloneDescriptor(p.descriptor)
}

// Fingerprint returns a mutable copy without sharing header or H2 slices.
// Identity-only selections return nil.
func (p *Profile) Fingerprint() *http.Fingerprint {
	if p == nil {
		return nil
	}

	return p.fingerprint.Clone()
}

func cloneDescriptor(descriptor Descriptor) Descriptor {
	descriptor.Sources = slices.Clone(descriptor.Sources)
	descriptor.Limitations = slices.Clone(descriptor.Limitations)

	return descriptor
}
