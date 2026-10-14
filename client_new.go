package http

// NewClient returns a Client that sends requests as profile describes. Its
// Transport is a new Transport with the same settings as DefaultTransport
// and Profile set to profile; it never shares connections with
// DefaultTransport or any other client. A nil profile returns a client with
// Go's TLS and HTTP behavior.
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
