package http

import (
	"crypto/tls"
	"errors"
	"slices"

	utls "github.com/refraction-networking/utls"
)

// configureUTLSPolicy applies the TLSClientConfig settings that interact
// with a profile ClientHello after uTLS has built its handshake state and
// before the ClientHello is marshaled again. The ClientHello's versions,
// cipher suites, and groups are the profile's; only Encrypted Client Hello
// narrows them, because it requires TLS 1.3.
func configureUTLSPolicy(conn *utls.UConn, config *utls.Config, original *tls.Config) error {
	if len(original.EncryptedClientHelloConfigList) > 0 {
		if err := requireTLS13(conn, config); err != nil {
			return err
		}
	}

	setRenegotiation(conn, utls.RenegotiationSupport(original.Renegotiation))

	return nil
}

// requireTLS13 limits a ClientHello to TLS 1.3, the only version that can
// carry Encrypted Client Hello. supported_versions keeps its GREASE value
// and loses every version below TLS 1.3. A ClientHello that does not offer
// TLS 1.3 is an error.
func requireTLS13(conn *utls.UConn, config *utls.Config) error {
	offered := false

	for _, extension := range conn.Extensions {
		versions, ok := extension.(*utls.SupportedVersionsExtension)
		if !ok {
			continue
		}

		versions.Versions = slices.DeleteFunc(versions.Versions, func(version uint16) bool {
			return !isGREASEValue(version) && version != tls.VersionTLS13
		})
		offered = slices.Contains(versions.Versions, tls.VersionTLS13)
	}

	if !offered {
		return errors.New("ECH requires TLS 1.3, but the ClientHello does not offer it")
	}

	if err := conn.SetTLSVers(tls.VersionTLS13, tls.VersionTLS13, conn.Extensions); err != nil {
		return err
	}

	config.MinVersion = tls.VersionTLS13
	config.MaxVersion = tls.VersionTLS13
	conn.HandshakeState.Hello.Vers = tls.VersionTLS12

	return nil
}

// setRenegotiation applies the caller's renegotiation policy through the
// renegotiation_info extension, which uTLS copies into its config when the
// configuration is applied. The extension stays on the wire either way.
func setRenegotiation(conn *utls.UConn, support utls.RenegotiationSupport) {
	for _, extension := range conn.Extensions {
		if renegotiation, ok := extension.(*utls.RenegotiationInfoExtension); ok {
			renegotiation.Renegotiation = support
		}
	}
}

// isGREASEValue reports whether value is a GREASE code point (RFC 8701),
// such as 0x0a0a or 0xfafa.
func isGREASEValue(value uint16) bool {
	return value&0x0f0f == 0x0a0a && byte(value) == byte(value>>8)
}
