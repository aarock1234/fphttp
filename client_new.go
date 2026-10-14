package http

import (
	"net"
	"time"
)

// NewClient returns a Client that sends requests as profile describes. Its
// Transport is a new Transport with Profile set to profile and the settings
// that DefaultTransport starts with: ProxyFromEnvironment, a 30-second dial
// timeout and keep-alive, ForceAttemptHTTP2, MaxIdleConns of 100, a
// 90-second IdleConnTimeout, a 10-second TLSHandshakeTimeout, and a 1-second
// ExpectContinueTimeout. It never shares connections with DefaultTransport
// or any other client, and changes to DefaultTransport do not affect it. A
// nil profile returns a client with Go's TLS and HTTP behavior.
//
// The Client and its Transport are ordinary values: the caller may change
// any of their fields, such as Client.Jar, Client.Timeout, or
// Transport.Proxy, before the first request. The Transport copies profile on
// first use, so changes to profile after that do not affect it. Call
// Client.CloseIdleConnections when the client is no longer needed.
func NewClient(profile *Profile) *Client {
	transport := newDefaultTransport()
	transport.Profile = profile

	return &Client{
		Transport: transport,
	}
}

// newDefaultTransport returns a new Transport with the settings that
// DefaultTransport starts with. It repeats the DefaultTransport literal in
// transport.go, which stays as upstream writes it so its documentation
// shows the settings; the two must change together.
func newDefaultTransport() *Transport {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &Transport{
		Proxy:                 ProxyFromEnvironment,
		DialContext:           defaultTransportDialContext(dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
