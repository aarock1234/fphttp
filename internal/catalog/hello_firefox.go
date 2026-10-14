package catalog

import (
	"fmt"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// firefoxHello builds a fresh ClientHello for a Firefox feature set from the
// uTLS Firefox 120 preset. It is safe for concurrent use: it reads features
// and copies every slice it places in the spec.
func firefoxHello(features *FirefoxWire) (*utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		return nil, fmt.Errorf("fphttp: construct Firefox hello: %w", err)
	}

	spec.CipherSuites = slices.DeleteFunc(spec.CipherSuites, func(cipher uint16) bool {
		return slices.Contains(features.DisabledCiphers, cipher)
	})

	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+2)
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			extension.Curves = firefoxCurves(features, extension.Curves)

		case *utls.KeyShareExtension:
			if features.MLKEM {
				extension.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, extension.KeyShares...)
			}

		case *utls.FakeDelegatedCredentialsExtension:
			extensions = append(extensions, extension)
			if features.SCT {
				extensions = append(extensions, &utls.SCTExtension{})
			}

			continue

		case *utls.GREASEEncryptedClientHelloExtension:
			// Certificate compression sits where the ECH extension is, even
			// when ECH itself is dropped.
			if len(features.CertCompression) > 0 {
				extensions = append(extensions, &utls.UtlsCompressCertExtension{
					Algorithms: slices.Clone(features.CertCompression),
				})
			}

			if !features.ECH {
				continue
			}
		}

		extensions = append(extensions, extension)
	}

	spec.Extensions = extensions

	return &spec, nil
}

// firefoxCurves returns the preset's supported groups without the FFDHE
// groups when features drop them, and with X25519MLKEM768 first when
// features enable ML-KEM.
func firefoxCurves(features *FirefoxWire, preset []utls.CurveID) []utls.CurveID {
	curves := preset

	if !features.FFDHE {
		curves = slices.DeleteFunc(curves, func(curve utls.CurveID) bool {
			return curve == utls.FakeCurveFFDHE2048 || curve == utls.FakeCurveFFDHE3072
		})
	}

	if features.MLKEM {
		curves = append([]utls.CurveID{utls.X25519MLKEM768}, curves...)
	}

	return curves
}
