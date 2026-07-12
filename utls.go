package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/httptrace"
)

// utlsConn wraps a *utls.UConn to satisfy the http2connectionStater
// interface, which requires ConnectionState() to return a standard
// crypto/tls.ConnectionState. The cached state is built once during
// the handshake and reused for the lifetime of the connection.
//
// TLS 1.3 does not allow renegotiation, and TLS 1.2 renegotiation is
// rare enough in browser-impersonation contexts that the cache cannot
// go stale in practice.
type utlsConn struct {
	*utls.UConn
	state tls.ConnectionState
}

// ConnectionState returns the cached crypto/tls connection state.
// This satisfies the http2connectionStater interface so that HTTP/2
// connections created from fingerprinted TLS connections have their
// TLS state available in Response.TLS.
func (c *utlsConn) ConnectionState() tls.ConnectionState {
	return c.state
}

// addTLSFingerprint performs a TLS handshake using uTLS to produce a
// browser-like ClientHello fingerprint. It replaces the standard
// addTLS path when Transport.Fingerprint is configured.
func (pconn *persistConn) addTLSFingerprint(ctx context.Context, name string, trace *httptrace.ClientTrace, fp *Fingerprint) error {
	cfg := utlsConfigFromTLS(pconn.t.TLSClientConfig, name)
	plainConn := pconn.conn
	tlsConn := utls.UClient(plainConn, cfg, fp.ClientHelloID)

	if fp.ClientHelloSpec != nil {
		if err := tlsConn.ApplyPreset(fp.ClientHelloSpec); err != nil {
			plainConn.Close()
			return fmt.Errorf("fphttp: applying ClientHelloSpec: %w", err)
		}
	}

	// A request that requires HTTP/1.1 (e.g. a WebSocket upgrade) must not let
	// the server negotiate h2. Browser presets advertise both "h2" and
	// "http/1.1" via ALPN, so rebuild the ClientHello with an http/1.1-only
	// ALPN. The rest of the fingerprint is preserved.
	if pconn.cacheKey.onlyH1 {
		if err := forceUTLSHTTP1(tlsConn); err != nil {
			plainConn.Close()
			return fmt.Errorf("fphttp: forcing http/1.1 ALPN: %w", err)
		}
	}

	if err := handshakeWithTimeout(ctx, tlsConn, pconn.t.TLSHandshakeTimeout, trace); err != nil {
		plainConn.Close()
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
		state: cs,
	}

	return nil
}

// handshakeWithTimeout runs the uTLS handshake with an optional timeout.
// A zero timeout means no timeout beyond ctx. The trace start hook is
// invoked before the handshake begins; the done hook is the caller's
// responsibility because it needs the final ConnectionState.
func handshakeWithTimeout(ctx context.Context, tlsConn *utls.UConn, timeout time.Duration, trace *httptrace.ClientTrace) error {
	errc := make(chan error, 2)

	var timer *time.Timer
	if timeout != 0 {
		timer = time.AfterFunc(timeout, func() {
			errc <- tlsHandshakeTimeoutError{}
		})
	}

	go func() {
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}

		err := tlsConn.HandshakeContext(ctx)
		if timer != nil {
			timer.Stop()
		}

		errc <- err
	}()

	err := <-errc
	if err == (tlsHandshakeTimeoutError{}) {
		// Drain the pending handshake goroutine after the timeout
		// has closed the connection out from under it.
		<-errc
	}

	return err
}

// utlsConfigFromTLS builds a utls.Config from an optional
// crypto/tls.Config, translating fields that map one-to-one.
// When tc is nil, the returned config has only ServerName set.
//
// For parity with crypto/tls, the verification callbacks, client
// certificates (mTLS to the origin), and KeyLogWriter are translated too.
//
// Fields intentionally not translated (uTLS-specific or rarely needed
// in impersonation use):
//   - ClientSessionCache (uTLS has its own cache interface)
//   - Rand, Time
//
// If you need these, construct a *utls.Config yourself and dial
// the connection outside of Transport.
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

	// VerifyConnection takes a package-local ConnectionState, so wrap the
	// caller's callback to convert from utls back to crypto/tls.
	if verify := tc.VerifyConnection; verify != nil {
		cfg.VerifyConnection = func(ucs utls.ConnectionState) error {
			return verify(convertUTLSConnectionState(ucs))
		}
	}

	// Client certificates for mTLS. uTLS uses its own Certificate and
	// CertificateRequestInfo types, so convert between them. The
	// reconstructed CertificateRequestInfo does not carry the handshake
	// context.
	if len(tc.Certificates) > 0 {
		cfg.Certificates = make([]utls.Certificate, len(tc.Certificates))
		for i := range tc.Certificates {
			cfg.Certificates[i] = toUTLSCertificate(tc.Certificates[i])
		}
	}
	if get := tc.GetClientCertificate; get != nil {
		cfg.GetClientCertificate = func(cri *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			cert, err := get(&tls.CertificateRequestInfo{
				AcceptableCAs:    cri.AcceptableCAs,
				SignatureSchemes: toTLSSignatureSchemes(cri.SignatureSchemes),
				Version:          cri.Version,
			})
			if err != nil {
				return nil, err
			}

			uc := toUTLSCertificate(*cert)
			return &uc, nil
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

// toTLSSignatureSchemes translates a slice of utls signature schemes to the
// equivalent crypto/tls signature schemes.
func toTLSSignatureSchemes(in []utls.SignatureScheme) []tls.SignatureScheme {
	if in == nil {
		return nil
	}

	out := make([]tls.SignatureScheme, len(in))
	for i, s := range in {
		out[i] = tls.SignatureScheme(s)
	}

	return out
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

// forceUTLSHTTP1 rewrites the connection's ClientHello so its ALPN offers
// only http/1.1. It must be called before the handshake. This is used for
// requests that require HTTP/1.1 (e.g. WebSocket upgrades), where a browser
// preset's default "h2, http/1.1" ALPN could otherwise let the server pick h2.
func forceUTLSHTTP1(c *utls.UConn) error {
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}

	for _, ext := range c.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}

	// Re-apply the mutated extensions and re-marshal so both the wire bytes
	// and the connection state reflect the http/1.1-only ALPN.
	if err := c.ApplyConfig(); err != nil {
		return err
	}

	return c.MarshalClientHello()
}

// convertUTLSConnectionState converts a utls ConnectionState to a
// standard crypto/tls ConnectionState.
//
// WARNING: audit this function whenever uTLS or crypto/tls add fields.
// The two structs are intentionally kept structurally similar, but
// they drift independently. Fields dropped here will not appear in
// Response.TLS.
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
	}
}
