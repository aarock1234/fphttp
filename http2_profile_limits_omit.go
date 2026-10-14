//go:build nethttpomithttp2 || nethttpomithttp2client

package http

// validateProfileHTTP2Limits accepts every Profile.HTTP2 when the HTTP/2
// client is omitted, because Profile.HTTP2 is never sent.
func (t *Transport) validateProfileHTTP2Limits(snapshot *Profile) error {
	return nil
}
