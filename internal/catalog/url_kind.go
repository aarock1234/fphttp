package catalog

// URLKind classifies a request URL by how far browsers trust it when they
// choose what to advertise, such as Brotli in Accept-Encoding. The zero
// value is URLInsecure. Values other than URLInsecure, URLLocalhost, and
// URLSecure are treated as URLInsecure.
type URLKind uint8

// Request URL kinds. The caller decides which hosts count as localhost.
const (
	// URLInsecure is a plain-http URL whose host is not localhost.
	URLInsecure URLKind = iota

	// URLLocalhost is a plain-http URL whose host is localhost, a
	// .localhost subdomain, or a loopback address.
	URLLocalhost

	// URLSecure is an https URL.
	URLSecure
)

// trustworthy reports whether the URL is potentially trustworthy in the
// sense Chromium and Firefox use for content encodings: https, or plain
// http to localhost.
func (k URLKind) trustworthy() bool {
	return k == URLSecure || k == URLLocalhost
}
