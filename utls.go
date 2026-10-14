package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/v2/httptrace"
)

// utlsConn wraps a *utls.UConn to satisfy the http2connectionStater
// interface, which requires a standard crypto/tls.ConnectionState.
type utlsConn struct {
	*utls.UConn
}

// wrapUTLSConn wraps a *utls.UConn returned by DialTLS or DialTLSContext so
// that its ConnectionState converts to crypto/tls. Other connections are
// returned unchanged, and a nil *utls.UConn becomes a nil net.Conn.
func wrapUTLSConn(conn net.Conn) net.Conn {
	if conn, ok := conn.(*utls.UConn); ok {
		if conn == nil {
			return nil
		}

		return &utlsConn{UConn: conn}
	}

	return conn
}

// ConnectionState returns the current crypto/tls connection metadata.
// This satisfies the http2connectionStater interface so that HTTP/2
// connections created from profile TLS connections have their TLS state
// available in Response.TLS.
func (c *utlsConn) ConnectionState() tls.ConnectionState {
	return convertUTLSConnectionState(c.UConn.ConnectionState())
}

// addProfileTLS performs the TLS handshake with uTLS so that the
// ClientHello is the one the Transport's profile snapshot describes. It
// replaces the crypto/tls handshake in addTLS when the profile has a
// NewHello. tlsConfig is the per-dial copy of TLSClientConfig with
// ServerName set.
func (pconn *persistConn) addProfileTLS(ctx context.Context, tlsConfig *tls.Config, trace *httptrace.ClientTrace) error {
	plainConn := pconn.conn
	config := pconn.profileUTLSConfig(tlsConfig)
	tlsConn := utls.UClient(plainConn, config, utls.HelloCustom)

	if err := applyProfileHello(tlsConn, pconn.t.profileState.snapshot.TLS.NewHello); err != nil {
		_ = plainConn.Close()

		return fmt.Errorf("fphttp: apply profile ClientHello: %w", err)
	}

	if err := pconn.configureUTLS(tlsConn, config, tlsConfig); err != nil {
		_ = plainConn.Close()

		return fmt.Errorf("fphttp: configure ClientHello: %w", err)
	}

	if err := handshakeWithTimeout(ctx, tlsConn, pconn.t.TLSHandshakeTimeout, trace); err != nil {
		_ = plainConn.Close()
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tls.ConnectionState{}, err)
		}

		return err
	}

	state := convertUTLSConnectionState(tlsConn.ConnectionState())
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(state, nil)
	}

	pconn.tlsState = &state
	pconn.conn = &utlsConn{
		UConn: tlsConn,
	}

	return nil
}

// profileUTLSConfig builds the uTLS configuration of one profile handshake
// from tlsConfig and the Transport's session cache.
//
// Session resumption: the catalog's ClientHellos carry no pre_shared_key
// extension, so TLS 1.3 sessions could never resume. AlwaysIncludePSK makes
// uTLS append one, last, in ApplyPreset, and OmitEmptyPsk keeps it off the
// wire until a cached session exists, as browsers do.
//
// Encrypted Client Hello: ApplyPreset appends pre_shared_key only when
// Config.MaxVersion is TLS 1.3 or later at that moment, and SetTLSVers fills
// MaxVersion from the spec only when no ECH config list is configured, so
// with a list AlwaysIncludePSK adds nothing (TLSClientConfig cannot set
// MaxVersion either). A NewHello that includes pre_shared_key itself cannot
// resume under ECH: MarshalClientHello rejects a loaded PSK with a real ECH
// config list ("PSK resumption with a custom ECH ClientHello is not
// supported"), which would fail every connection after the first. ECH
// connections therefore get no session cache and always perform a full
// handshake. GREASE ECH takes neither path and resumes normally.
func (pconn *persistConn) profileUTLSConfig(tlsConfig *tls.Config) *utls.Config {
	config := utlsConfigFromTLS(tlsConfig, tlsConfig.ServerName)
	config.PreferSkipResumptionOnNilExtension = true
	config.OmitEmptyPsk = true

	cache := pconn.t.profileState.sessionCache
	if cache != nil && len(tlsConfig.EncryptedClientHelloConfigList) == 0 {
		config.ClientSessionCache = cache
		config.AlwaysIncludePSK = true
	}

	if pconn.cacheKey.onlyH1 {
		config.NextProtos = []string{"http/1.1"}
	}

	return config
}

// handshakeWithTimeout runs the uTLS handshake with an optional timeout.
// A zero timeout means no timeout beyond ctx. The trace start hook is
// invoked before the handshake begins; the done hook is the caller's
// responsibility because it needs the final ConnectionState.
func handshakeWithTimeout(ctx context.Context, tlsConn *utls.UConn, timeout time.Duration, trace *httptrace.ClientTrace) error {
	handshakeCtx := ctx
	var cancel context.CancelFunc
	if timeout != 0 {
		handshakeCtx, cancel = context.WithTimeoutCause(ctx, timeout, tlsHandshakeTimeoutError{})
		defer cancel()
	}

	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}

	err := tlsConn.HandshakeContext(handshakeCtx)
	if err != nil && errors.Is(context.Cause(handshakeCtx), tlsHandshakeTimeoutError{}) {
		return tlsHandshakeTimeoutError{}
	}

	return err
}

// utlsConfigFromTLS builds a utls.Config from an optional
// crypto/tls.Config, translating the fields that do not shape the
// ClientHello. When tc is nil, the returned config has only ServerName set.
//
// MinVersion, MaxVersion, CipherSuites, CurvePreferences, and
// ClientSessionCache are not translated: the profile owns the ClientHello,
// and the Transport rejects a TLSClientConfig that sets them. Verification
// callbacks, client certificates and their selection callback, Rand, Time,
// Renegotiation, KeyLogWriter, and the ECH settings are translated.
func utlsConfigFromTLS(tc *tls.Config, serverName string) *utls.Config {
	cfg := &utls.Config{
		ServerName: serverName,
	}
	if tc == nil {
		return cfg
	}

	if tc.ServerName != "" {
		cfg.ServerName = tc.ServerName
	}
	cfg.InsecureSkipVerify = tc.InsecureSkipVerify
	cfg.Rand = tc.Rand
	cfg.Time = tc.Time
	cfg.RootCAs = tc.RootCAs
	cfg.NextProtos = tc.NextProtos
	cfg.PreferServerCipherSuites = tc.PreferServerCipherSuites
	cfg.SessionTicketsDisabled = tc.SessionTicketsDisabled
	cfg.DynamicRecordSizingDisabled = tc.DynamicRecordSizingDisabled
	cfg.Renegotiation = utls.RenegotiationSupport(tc.Renegotiation)
	cfg.VerifyPeerCertificate = tc.VerifyPeerCertificate
	cfg.KeyLogWriter = tc.KeyLogWriter
	cfg.EncryptedClientHelloConfigList = tc.EncryptedClientHelloConfigList
	if verify := tc.EncryptedClientHelloRejectionVerify; verify != nil {
		cfg.EncryptedClientHelloRejectionVerify = func(state utls.ConnectionState) error {
			return verify(convertUTLSConnectionState(state))
		}
	}

	// VerifyConnection takes a package-local ConnectionState, so wrap the
	// caller's callback to convert from utls back to crypto/tls.
	if verify := tc.VerifyConnection; verify != nil {
		cfg.VerifyConnection = func(ucs utls.ConnectionState) error {
			return verify(convertUTLSConnectionState(ucs))
		}
	}

	// Static client certificates use the same key and certificate types.
	if len(tc.Certificates) > 0 {
		cfg.Certificates = make([]utls.Certificate, len(tc.Certificates))
		for i := range tc.Certificates {
			cfg.Certificates[i] = toUTLSCertificate(tc.Certificates[i])
		}
	}

	if get := tc.GetClientCertificate; get != nil {
		cfg.GetClientCertificate = utlsGetClientCertificate(get)
	}

	return cfg
}

// utlsGetClientCertificate adapts a crypto/tls certificate selection
// callback to uTLS. A nil certificate with a nil error, which crypto/tls
// forbids, becomes an error instead of a panic during the handshake.
//
// The request passed to get has no handshake context: crypto/tls stores it
// in an unexported field that only crypto/tls can set, so Context returns
// nil. Callbacks that need a deadline must use their own.
func utlsGetClientCertificate(get func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) func(*utls.CertificateRequestInfo) (*utls.Certificate, error) {
	return func(info *utls.CertificateRequestInfo) (*utls.Certificate, error) {
		certificate, err := get(&tls.CertificateRequestInfo{
			AcceptableCAs:    info.AcceptableCAs,
			SignatureSchemes: toTLSSignatureSchemes(info.SignatureSchemes),
			Version:          info.Version,
		})
		if err != nil {
			return nil, err
		}

		if certificate == nil {
			return nil, errors.New("fphttp: GetClientCertificate returned a nil certificate")
		}

		converted := toUTLSCertificate(*certificate)

		return &converted, nil
	}
}

// toTLSSignatureSchemes converts uTLS signature schemes to crypto/tls. Both
// are the same uint16 registry values.
func toTLSSignatureSchemes(schemes []utls.SignatureScheme) []tls.SignatureScheme {
	if schemes == nil {
		return nil
	}

	converted := make([]tls.SignatureScheme, len(schemes))
	for index, scheme := range schemes {
		converted[index] = tls.SignatureScheme(scheme)
	}

	return converted
}

// toUTLSCertificate converts a crypto/tls.Certificate to the equivalent
// utls.Certificate. The two types are structurally identical.
func toUTLSCertificate(c tls.Certificate) utls.Certificate {
	uc := utls.Certificate{
		Certificate:                 c.Certificate,
		PrivateKey:                  c.PrivateKey,
		OCSPStaple:                  c.OCSPStaple,
		SignedCertificateTimestamps: c.SignedCertificateTimestamps,
		Leaf:                        c.Leaf,
	}

	if c.SupportedSignatureAlgorithms != nil {
		uc.SupportedSignatureAlgorithms = make([]utls.SignatureScheme, len(c.SupportedSignatureAlgorithms))
		for i, s := range c.SupportedSignatureAlgorithms {
			uc.SupportedSignatureAlgorithms[i] = utls.SignatureScheme(s)
		}
	}

	return uc
}

// configureUTLS builds the handshake state of a profile ClientHello and
// applies the transport's policy to it: the ECH and renegotiation settings
// of TLSClientConfig, then the protocols the connection may negotiate.
// It marshals the final ClientHello.
func (pconn *persistConn) configureUTLS(c *utls.UConn, config *utls.Config, original *tls.Config) error {
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}

	if err := configureUTLSPolicy(c, config, original); err != nil {
		return err
	}

	if err := pconn.filterApplicationProtocols(c); err != nil {
		return err
	}

	if err := c.ApplyConfig(); err != nil {
		return err
	}

	return c.MarshalClientHello()
}

// filterApplicationProtocols limits the ALPN and ALPS extensions to the
// protocols this connection may use. A ClientHello that offers a protocol
// the transport cannot speak, or none it can, is an error.
func (pconn *persistConn) filterApplicationProtocols(c *utls.UConn) error {
	protocols := pconn.t.protocols()
	allowHTTP2 := protocols.HTTP2() && !pconn.cacheKey.onlyH1 && pconn.t.h2Transport != nil && !omitHTTP2Client
	allowHTTP1 := protocols.HTTP1() || pconn.cacheKey.onlyH1

	if !allowHTTP2 {
		c.Extensions = slices.DeleteFunc(c.Extensions, func(extension utls.TLSExtension) bool {
			switch extension.(type) {
			case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
				return true
			default:
				return false
			}
		})
	}

	for _, extension := range c.Extensions {
		alpn, ok := extension.(*utls.ALPNExtension)
		if !ok {
			continue
		}

		filtered := slices.DeleteFunc(slices.Clone(alpn.AlpnProtocols), func(protocol string) bool {
			return (protocol == "h2" && !allowHTTP2) || (protocol == "http/1.1" && !allowHTTP1)
		})
		for _, protocol := range filtered {
			if protocol != "h2" && protocol != "http/1.1" {
				return fmt.Errorf("unsupported application protocol %q", protocol)
			}
		}

		if len(filtered) == 0 {
			return errors.New("ClientHello ALPN has no protocol enabled by the transport")
		}

		alpn.AlpnProtocols = filtered
	}

	return nil
}

// convertUTLSConnectionState converts a utls ConnectionState to a
// standard crypto/tls ConnectionState.
//
// Audit this conversion whenever either TLS package adds fields.
// ExportKeyingMaterial on the result uses the uTLS connection's exporter
// (see setKeyingMaterialExporter).
func convertUTLSConnectionState(ucs utls.ConnectionState) tls.ConnectionState {
	state := tls.ConnectionState{
		Version:                     ucs.Version,
		HandshakeComplete:           ucs.HandshakeComplete,
		DidResume:                   ucs.DidResume,
		CipherSuite:                 ucs.CipherSuite,
		CurveID:                     tls.CurveID(ucs.CurveID),
		NegotiatedProtocol:          ucs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  ucs.NegotiatedProtocolIsMutual,
		ServerName:                  ucs.ServerName,
		PeerCertificates:            ucs.PeerCertificates,
		VerifiedChains:              ucs.VerifiedChains,
		SignedCertificateTimestamps: ucs.SignedCertificateTimestamps,
		OCSPResponse:                ucs.OCSPResponse,
		TLSUnique:                   ucs.TLSUnique,
		ECHAccepted:                 ucs.ECHAccepted,
		HelloRetryRequest:           ucs.HelloRetryRequest,
		LocalCertificate:            ucs.LocalCertificate,
	}
	setKeyingMaterialExporter(&state, ucs)

	return state
}
