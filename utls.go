package http

import (
	"context"
	"crypto/tls"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/httptrace"
)

// utlsConn wraps a *utls.UConn to satisfy the http2connectionStater
// interface, which requires ConnectionState() to return a standard
// crypto/tls.ConnectionState. The cached state is built once during
// the handshake and reused for the lifetime of the connection.
type utlsConn struct {
	*utls.UConn
	state tls.ConnectionState
}

// ConnectionState returns the standard crypto/tls connection state.
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
	cfg := &utls.Config{
		ServerName: name,
	}

	// Inherit relevant fields from TLSClientConfig.
	if tc := pconn.t.TLSClientConfig; tc != nil {
		if tc.ServerName != "" {
			cfg.ServerName = tc.ServerName
		}
		cfg.InsecureSkipVerify = tc.InsecureSkipVerify
		cfg.RootCAs = tc.RootCAs
	}

	plainConn := pconn.conn
	tlsConn := utls.UClient(plainConn, cfg, fp.ClientHelloID)

	errc := make(chan error, 2)
	var timer *time.Timer
	if d := pconn.t.TLSHandshakeTimeout; d != 0 {
		timer = time.AfterFunc(d, func() {
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

	if err := <-errc; err != nil {
		plainConn.Close()
		if err == (tlsHandshakeTimeoutError{}) {
			<-errc
		}
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

// convertUTLSConnectionState converts a utls ConnectionState to a
// standard crypto/tls ConnectionState. Both types are structurally
// identical but come from different packages.
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
