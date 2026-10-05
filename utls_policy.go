package http

import (
	"crypto/tls"
	"errors"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// Browser presets overwrite parts of uTLS's config during initialization.
// Apply the caller's security policy after that step, before marshaling again.
// Restrictions keep the preset's relative order but can change its fingerprint.
func configureUTLSPolicy(conn *utls.UConn, config *utls.Config, original *tls.Config) error {
	minVersion := max(config.MinVersion, tls.VersionTLS12)
	if original.MinVersion != 0 {
		minVersion = max(config.MinVersion, original.MinVersion)
	}
	maxVersion := config.MaxVersion
	if original.MaxVersion != 0 {
		maxVersion = min(maxVersion, original.MaxVersion)
	}
	if len(original.EncryptedClientHelloConfigList) > 0 {
		minVersion = max(minVersion, tls.VersionTLS13)
	}
	if minVersion > maxVersion {
		return errors.New("TLS version policy has no version in common with the ClientHello")
	}
	if err := conn.SetTLSVers(minVersion, maxVersion, conn.Extensions); err != nil {
		return err
	}
	config.MinVersion = minVersion
	config.MaxVersion = maxVersion
	conn.HandshakeState.Hello.Vers = min(maxVersion, tls.VersionTLS12)

	for _, extension := range conn.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedVersionsExtension:
			extension.Versions = slices.DeleteFunc(extension.Versions, func(version uint16) bool {
				return !isGREASEValue(version) && (version < minVersion || version > maxVersion)
			})
		case *utls.RenegotiationInfoExtension:
			extension.Renegotiation = utls.RenegotiationSupport(original.Renegotiation)
		}
	}

	if err := restrictUTLSCipherSuites(conn, original.CipherSuites, maxVersion); err != nil {
		return err
	}
	if len(original.CurvePreferences) > 0 {
		return restrictUTLSCurves(conn, original.CurvePreferences)
	}

	return nil
}

func restrictUTLSCipherSuites(conn *utls.UConn, allowed []uint16, maxVersion uint16) error {
	hello := conn.HandshakeState.Hello
	hello.CipherSuites = slices.DeleteFunc(hello.CipherSuites, func(suite uint16) bool {
		if isGREASEValue(suite) {
			return false
		}
		if suite >= utls.TLS_AES_128_GCM_SHA256 && suite <= utls.TLS_CHACHA20_POLY1305_SHA256 {
			return maxVersion < tls.VersionTLS13
		}

		return allowed != nil && !slices.Contains(allowed, suite)
	})
	for _, suite := range hello.CipherSuites {
		if !isGREASEValue(suite) {
			return nil
		}
	}

	return errors.New("TLS cipher suite policy has no suite in common with the ClientHello")
}

func restrictUTLSCurves(conn *utls.UConn, allowed []tls.CurveID) error {
	curves := convertCurveIDs(allowed)
	for _, extension := range conn.Extensions {
		switch extension := extension.(type) {
		case *utls.SupportedCurvesExtension:
			extension.Curves = slices.DeleteFunc(extension.Curves, func(curve utls.CurveID) bool {
				return !isGREASEValue(uint16(curve)) && !slices.Contains(curves, curve)
			})
			if !slices.ContainsFunc(extension.Curves, func(curve utls.CurveID) bool {
				return !isGREASEValue(uint16(curve))
			}) {
				return errors.New("TLS curve policy has no group in common with the ClientHello")
			}
		case *utls.KeyShareExtension:
			extension.KeyShares = slices.DeleteFunc(extension.KeyShares, func(share utls.KeyShare) bool {
				return !isGREASEValue(uint16(share.Group)) && !slices.Contains(curves, share.Group)
			})
		}
	}

	return nil
}

func isGREASEValue(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value) == byte(value>>8)
}
