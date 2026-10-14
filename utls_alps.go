package http

// PeerApplicationSettings returns the application settings the server sent
// in its ALPS extension for the negotiated protocol, or nil when it sent
// none. For h2 they are HTTP/2 frames, which the HTTP/2 transport applies
// before the server's first SETTINGS frame, as Chromium does.
func (c *utlsConn) PeerApplicationSettings() []byte {
	return c.UConn.ConnectionState().PeerApplicationSettings
}
