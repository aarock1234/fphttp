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

	"github.com/aarock1234/fphttp/httptrace"
)

// utlsConn wraps a *utls.UConn to satisfy the http2connectionStater
// interface, which requires a standard crypto/tls.ConnectionState.
type utlsConn struct {
	*utls.UConn
}

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
// connections created from fingerprinted TLS connections have their
// TLS state available in Response.TLS.
func (c *utlsConn) ConnectionState() tls.ConnectionState {
	return convertUTLSConnectionState(c.UConn.ConnectionState())
}

// addTLSFingerprint performs a TLS handshake using uTLS to produce a
// browser-like ClientHello fingerprint. It replaces the standard
// addTLS path when Transport.Fingerprint is configured.
func (pconn *persistConn) addTLSFingerprint(ctx context.Context, tlsConfig *tls.Config, trace *httptrace.ClientTrace, fp *Fingerprint) error {
	plainConn := pconn.conn
	cfg := utlsConfigFromTLS(tlsConfig, tlsConfig.ServerName)
	cfg.ClientSessionCache = fp.ClientSessionCache
	cfg.GetClientCertificate = fp.GetClientCertificate
	cfg.PreferSkipResumptionOnNilExtension = true
	cfg.OmitEmptyPsk = true
	if get := cfg.GetClientCertificate; get != nil {
		cfg.GetClientCertificate = func(info *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			certificate, err := get(info)
			if err == nil && certificate == nil {
				err = errors.New("fphttp: GetClientCertificate returned a nil certificate")
			}

			return certificate, err
		}
	}
	if pconn.cacheKey.onlyH1 {
		cfg.NextProtos = []string{"http/1.1"}
	}

	helloID := fp.ClientHelloID
	if fp.ClientHelloSpec != nil || fp.ClientHelloSpecFactory != nil {
		helloID = utls.HelloCustom
	}
	tlsConn := utls.UClient(plainConn, cfg, helloID)

	if helloID == utls.HelloCustom {
		spec, err := fp.newClientHelloSpec()
		if err == nil {
			err = tlsConn.ApplyPreset(spec)
		}
		if err != nil {
			_ = plainConn.Close()
			return fmt.Errorf("fphttp: apply custom ClientHello: %w", err)
		}
	}

	if err := pconn.configureUTLS(tlsConn, cfg, tlsConfig); err != nil {
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

	cs := convertUTLSConnectionState(tlsConn.ConnectionState())
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(cs, nil)
	}

	pconn.tlsState = &cs
	pconn.conn = &utlsConn{
		UConn: tlsConn,
	}

	return nil
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

func (f *Fingerprint) newClientHelloSpec() (*utls.ClientHelloSpec, error) {
	if f.ClientHelloSpecFactory != nil {
		spec, err := f.ClientHelloSpecFactory()
		if err != nil {
			return nil, err
		}
		if spec == nil {
			return nil, errors.New("ClientHelloSpecFactory returned a nil spec")
		}
		if err := validateClientHelloExtensions(spec); err != nil {
			return nil, err
		}

		return spec, nil
	}
	if f.ClientHelloSpec == nil {
		return nil, errors.New("HelloCustom requires ClientHelloSpec or ClientHelloSpecFactory")
	}

	return cloneClientHelloSpec(f.ClientHelloSpec)
}

// utlsConfigFromTLS builds a utls.Config from an optional
// crypto/tls.Config, translating fields that map one-to-one.
// When tc is nil, the returned config has only ServerName set.
//
// Verification callbacks, static client certificates, Rand, Time, and
// KeyLogWriter are translated. Session caches and certificate selection
// callbacks use the uTLS types exposed by Fingerprint.
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
	cfg.MinVersion = tc.MinVersion
	cfg.MaxVersion = tc.MaxVersion
	cfg.CipherSuites = tc.CipherSuites
	cfg.CurvePreferences = convertCurveIDs(tc.CurvePreferences)
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

	return cfg
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

// convertCurveIDs translates a slice of crypto/tls.CurveID to
// utls.CurveID. Both are uint16 under the hood.
func convertCurveIDs(in []tls.CurveID) []utls.CurveID {
	if len(in) == 0 {
		return nil
	}

	out := make([]utls.CurveID, len(in))
	for i, c := range in {
		out[i] = utls.CurveID(c)
	}

	return out
}

func (pconn *persistConn) configureUTLS(c *utls.UConn, config *utls.Config, original *tls.Config) error {
	if c.ClientHelloID == utls.HelloGolang {
		return nil
	}
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	if err := configureUTLSPolicy(c, config, original); err != nil {
		return err
	}

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
		switch extension := extension.(type) {
		case *utls.ALPNExtension:
			filtered := slices.DeleteFunc(slices.Clone(extension.AlpnProtocols), func(protocol string) bool {
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
			extension.AlpnProtocols = filtered
		}
	}

	if err := c.ApplyConfig(); err != nil {
		return err
	}

	return c.MarshalClientHello()
}

// convertUTLSConnectionState converts a utls ConnectionState to a
// standard crypto/tls ConnectionState.
//
// Audit this conversion whenever either TLS package adds fields. uTLS's
// private negotiated curve and crypto/tls's private keying-material exporter
// cannot be translated. Callers must not use ExportKeyingMaterial on this state.
func convertUTLSConnectionState(ucs utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     ucs.Version,
		HandshakeComplete:           ucs.HandshakeComplete,
		DidResume:                   ucs.DidResume,
		CipherSuite:                 ucs.CipherSuite,
		NegotiatedProtocol:          ucs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  ucs.NegotiatedProtocolIsMutual,
		ServerName:                  ucs.ServerName,
		PeerCertificates:            ucs.PeerCertificates,
		VerifiedChains:              ucs.VerifiedChains,
		SignedCertificateTimestamps: ucs.SignedCertificateTimestamps,
		OCSPResponse:                ucs.OCSPResponse,
		TLSUnique:                   ucs.TLSUnique,
		ECHAccepted:                 ucs.ECHAccepted,
	}
}
