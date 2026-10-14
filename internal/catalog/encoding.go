package catalog

// Accept-Encoding values.
const (
	// encodingsBasic is sent where the browser does not advertise Brotli,
	// such as a plain-http URL whose host is not localhost.
	encodingsBasic = "gzip, deflate"

	// encodingsBrotli adds Brotli where the browser advertises it.
	encodingsBrotli = "gzip, deflate, br"

	// encodingsBrotliZstd adds Zstandard after Brotli.
	encodingsBrotliZstd = "gzip, deflate, br, zstd"

	// chromiumMediaEncoding is what Chromium's media loader requests for
	// audio and video, together with the Range field Entry.Range returns.
	chromiumMediaEncoding = "identity;q=1, *;q=0"

	// firefoxFontEncoding is what Firefox requests for a font whose
	// @font-face source carries a format("woff") or format("woff2") hint,
	// since those formats are already compressed. FontPreloader.cpp sets it
	// at ESR 102.15.1, 108, and 115, and FontLoaderUtils.cpp at 144.
	firefoxFontEncoding = "identity"
)

// First releases that advertise Zstandard next to Brotli.
const (
	// chromiumZstdMajor enables ZstdContentEncoding by default.
	chromiumZstdMajor = 123

	// firefoxZstdMajor adds zstd to network.http.accept-encoding.secure.
	firefoxZstdMajor = 126

	// safariZstdRelease added Zstandard content encoding.
	safariZstdRelease = "26.3"
)

// AcceptEncoding returns the Accept-Encoding value the release sends for a
// request destination (see Accept) to a URL of the given kind. It returns ""
// for an unknown destination.
//
// Chromium and Firefox advertise Brotli and Zstandard to https URLs and to
// plain-http localhost URLs. Safari advertises them to https URLs only; its
// localhost behavior was not captured and keeps fphttp v1's. A WebSocket
// handshake gets the same network default from Chromium and Firefox
// (URLRequestHttpJob::AddExtraHeaders, nsHttpHandler) and none from Safari.
//
// Chromium sends "identity" instead when a request carries a Range field
// but no Accept-Encoding of its own. The caller applies that rule, because
// it depends on the request's fields. The rule never replaces the audio and
// video value: Chromium's media loader sets that Accept-Encoding itself,
// together with the Range field that Range returns.
func (e Entry) AcceptEncoding(destination string, target URLKind) string {
	kind := parseDestination(destination)
	if kind == destinationUnknown {
		return ""
	}

	switch e.Family {
	case FamilyChromium:
		return e.chromiumAcceptEncoding(kind, target)
	case FamilyFirefox:
		return e.firefoxAcceptEncoding(kind, target)
	case FamilySafari:
		return e.safariAcceptEncoding(kind, target)
	default:
		return ""
	}
}

// chromiumAcceptEncoding returns Chromium's Accept-Encoding. Audio and video
// requests set their own value; everything else gets the network default,
// with Brotli and Zstandard for https and localhost (IsLocalhost).
func (e Entry) chromiumAcceptEncoding(destination fetchDestination, target URLKind) string {
	if destination.media() {
		return chromiumMediaEncoding
	}

	return contentEncodings(target.trustworthy(), e.chromiumMajor() >= chromiumZstdMajor)
}

// firefoxAcceptEncoding returns Firefox's Accept-Encoding, with Brotli and
// Zstandard for https and localhost
// (network.http.encoding.trustworthy_is_https). Fonts model the common
// @font-face source with a WOFF or WOFF2 format hint. Media requests were
// not traced and keep fphttp v1's network default.
func (e Entry) firefoxAcceptEncoding(destination fetchDestination, target URLKind) string {
	if destination == destinationFont {
		return firefoxFontEncoding
	}

	return contentEncodings(target.trustworthy(), e.Major() >= firefoxZstdMajor)
}

// safariAcceptEncoding returns Safari's Accept-Encoding: Zstandard from
// 26.3, so Safari 27 sends it and Safari 26.0 does not. Plain-http values,
// localhost included, and media requests were not captured and keep fphttp
// v1's behavior, which advertises Brotli to https URLs only. A WebSocket
// handshake, which CFNetwork builds, gets none, because its fields were not
// verified.
func (e Entry) safariAcceptEncoding(destination fetchDestination, target URLKind) string {
	if destination == destinationWebSocket {
		return ""
	}

	return contentEncodings(target == URLSecure, versionAtLeast(e.Version, safariZstdRelease))
}

// contentEncodings returns the network default list: gzip and deflate
// everywhere, plus Brotli and optionally Zstandard where the browser
// advertises them.
func contentEncodings(brotli, zstd bool) string {
	switch {
	case !brotli:
		return encodingsBasic
	case zstd:
		return encodingsBrotliZstd
	default:
		return encodingsBrotli
	}
}
