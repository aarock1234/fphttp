package http

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestForceUTLSHTTP1 verifies that forceUTLSHTTP1 rewrites a browser preset's
// ClientHello so its ALPN offers only http/1.1, without performing a handshake.
func TestForceUTLSHTTP1(t *testing.T) {
	c, s := net.Pipe()
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})

	uconn := utls.UClient(c, &utls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	if err := forceUTLSHTTP1(uconn); err != nil {
		t.Fatalf("forceUTLSHTTP1: %v", err)
	}

	got := uconn.HandshakeState.Hello.AlpnProtocols
	if len(got) != 1 || got[0] != "http/1.1" {
		t.Errorf("ALPN = %v, want [http/1.1]", got)
	}
}

// TestUTLSConfigFromTLS_Parity verifies that the crypto/tls verification
// callbacks, client certificates, and KeyLogWriter are translated into the
// uTLS config, so fingerprinting keeps parity with the standard library.
func TestUTLSConfigFromTLS_Parity(t *testing.T) {
	keyLog := &nopWriter{}
	cert := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}}

	tc := &tls.Config{
		KeyLogWriter:          keyLog,
		VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error { return nil },
		VerifyConnection:      func(tls.ConnectionState) error { return nil },
		Certificates:          []tls.Certificate{cert},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	cfg := utlsConfigFromTLS(tc, "example.com")

	if cfg.KeyLogWriter != keyLog {
		t.Error("KeyLogWriter not propagated")
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate not propagated")
	}
	if cfg.VerifyConnection == nil {
		t.Error("VerifyConnection not propagated")
	}
	if len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) != 1 {
		t.Errorf("Certificates not propagated: %+v", cfg.Certificates)
	}

	if cfg.GetClientCertificate == nil {
		t.Fatal("GetClientCertificate not propagated")
	}
	got, err := cfg.GetClientCertificate(&utls.CertificateRequestInfo{})
	if err != nil || got == nil || len(got.Certificate) != 1 {
		t.Errorf("GetClientCertificate adapter returned (%+v, %v)", got, err)
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
