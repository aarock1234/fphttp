package catalog

import (
	"fmt"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// clientHelloID returns the uTLS preset of a Chromium hello. The ECH,
// Kyber, and ML-KEM presets already shuffle their extensions inside uTLS.
func (h ChromiumHello) clientHelloID() (utls.ClientHelloID, bool) {
	switch h {
	case ChromiumHelloClassical:
		return utls.HelloChrome_102, true
	case ChromiumHelloECH:
		return utls.HelloChrome_120, true
	case ChromiumHelloKyber:
		return utls.HelloChrome_120_PQ, true
	case ChromiumHelloMLKEM:
		return utls.HelloChrome_131, true
	default:
		return utls.ClientHelloID{}, false
	}
}

// chromiumHello builds a fresh ClientHello for a Chromium feature set. It
// is safe for concurrent use: it reads features and copies every slice it
// places in the spec.
func chromiumHello(features *ChromiumWire) (*utls.ClientHelloSpec, error) {
	helloID, ok := features.Hello.clientHelloID()
	if !ok {
		return nil, fmt.Errorf("fphttp: unknown Chromium hello %d", features.Hello)
	}

	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		return nil, fmt.Errorf("fphttp: construct Chromium hello: %w", err)
	}

	for index, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.ApplicationSettingsExtension:
			if features.NewALPS {
				spec.Extensions[index] = &utls.ApplicationSettingsExtensionNew{
					SupportedProtocols: slices.Clone(extension.SupportedProtocols),
				}
			}

		case *utls.SignatureAlgorithmsExtension:
			extension.SupportedSignatureAlgorithms = chromiumSignatureAlgorithms(features, extension.SupportedSignatureAlgorithms)
		}
	}

	if len(features.TrustAnchorIDs) > 0 {
		anchors := &utls.TrustAnchorsExtension{
			TrustAnchorIDs: cloneTrustAnchorIDs(features.TrustAnchorIDs),
		}

		// Chromium places the extension before the trailing GREASE extension.
		last := len(spec.Extensions) - 1
		spec.Extensions = slices.Insert(spec.Extensions, last, utls.TLSExtension(anchors))
	}

	if features.Shuffle {
		spec.Extensions = utls.ShuffleChromeTLSExtensions(spec.Extensions)
	}

	return &spec, nil
}

// chromiumSignatureAlgorithms returns a copy of the preset's signature
// algorithms with ML-DSA and then GREASE prepended as features require, so
// GREASE comes first.
func chromiumSignatureAlgorithms(features *ChromiumWire, preset []utls.SignatureScheme) []utls.SignatureScheme {
	algorithms := slices.Clone(preset)

	if features.MLDSA {
		algorithms = append([]utls.SignatureScheme{
			utls.MLDSA44,
			utls.MLDSA65,
			utls.MLDSA87,
		}, algorithms...)
	}

	if features.SignatureGREASE {
		algorithms = append([]utls.SignatureScheme{utls.GREASE_PLACEHOLDER}, algorithms...)
	}

	return algorithms
}

// cloneTrustAnchorIDs copies the IDs so a ClientHello never shares storage
// with the catalog.
func cloneTrustAnchorIDs(ids [][]byte) [][]byte {
	clones := make([][]byte, len(ids))
	for index, id := range ids {
		clones[index] = slices.Clone(id)
	}

	return clones
}
