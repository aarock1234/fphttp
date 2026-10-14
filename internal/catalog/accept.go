package catalog

// Accept values every engine family shares.
const (
	// acceptAny is the default for scripts, fetch(), XMLHttpRequest, and
	// most other subresources.
	acceptAny = "*/*"

	// acceptStylesheet is the stylesheet Accept of Chromium, Firefox, and
	// Safari.
	acceptStylesheet = "text/css,*/*;q=0.1"
)

// Chromium Accept values, from content/common/content_constants_internal.h,
// content/browser/web_package/signed_exchange_consts.h, and
// third_party/blink/common/loader/network_utils.cc. AVIF is listed on every
// platform, Android included.
const (
	// chromiumFrameAccept108 is the frame navigation Accept without the
	// signed exchange suffix.
	chromiumFrameAccept108 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"

	// chromiumFrameAccept155 adds JPEG XL, enabled by default from 155.
	chromiumFrameAccept155 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8"

	// chromiumSignedExchange108 is Chrome's signed exchange suffix in 108
	// and 109.
	chromiumSignedExchange108 = ",application/signed-exchange;v=b3;q=0.9"

	// chromiumSignedExchange110 is Chrome's signed exchange suffix from 110.
	chromiumSignedExchange110 = ",application/signed-exchange;v=b3;q=0.7"

	// chromiumImageAccept108 is the image Accept before JPEG XL.
	chromiumImageAccept108 = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"

	// chromiumImageAccept155 adds JPEG XL, enabled by default from 155.
	chromiumImageAccept155 = "image/jxl,image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
)

// Chromium majors where an Accept value changes.
const (
	// chromiumSignedExchange110Major lowers the signed exchange quality to
	// 0.7.
	chromiumSignedExchange110Major = 110

	// chromiumJXLMajor enables JPEG XL (kJXLImageFormat) by default.
	chromiumJXLMajor = 155
)

// Firefox Accept values, from netwerk/protocol/http/nsHttpHandler.cpp,
// layout/style/FontPreloader.cpp and FontLoaderUtils.cpp, and the media
// element sources.
const (
	// firefoxDocumentAccept102 is the document Accept through 127 and in
	// ESR 102 and 115.
	firefoxDocumentAccept102 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

	// firefoxDocumentAccept128 lists more image types, in stable 128 to
	// 131.
	firefoxDocumentAccept128 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"

	// firefoxDocumentAccept132 drops image types
	// (network.http.accept.include_images false), from stable 132 and ESR
	// 128.7.
	firefoxDocumentAccept132 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

	// firefoxImageAccept102 is the image Accept through 127 and in ESR 102
	// and 115.
	firefoxImageAccept102 = "image/avif,image/webp,*/*"

	// firefoxImageAccept128 is the image Accept from 128, ESR included.
	firefoxImageAccept128 = "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"

	// firefoxImageAccept158 adds JPEG XL, enabled by default from 158.
	firefoxImageAccept158 = "image/avif,image/jxl,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"

	// firefoxFontAccept is the @font-face Accept in every cataloged
	// release, ESR 102 included: FontPreloader.cpp sets it at ESR 102.15.1,
	// 108, and 115, and FontLoaderUtils.cpp at 144.
	firefoxFontAccept = "application/font-woff2;q=1.0,application/font-woff;q=0.9,*/*;q=0.8"

	// firefoxAudioAccept is the audio element Accept.
	firefoxAudioAccept = "audio/webm,audio/ogg,audio/wav,audio/*;q=0.9,application/ogg;q=0.7,video/*;q=0.6,*/*;q=0.5"

	// firefoxVideoAccept is the video element Accept.
	firefoxVideoAccept = "video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5"
)

// Firefox majors where an Accept value changes.
const (
	// firefoxAccept128Major adds image types to the document and image
	// Accept values.
	firefoxAccept128Major = 128

	// firefoxDocumentAccept132Major drops image types from the document
	// Accept.
	firefoxDocumentAccept132Major = 132

	// firefoxImageAccept158Major adds JPEG XL to the image Accept.
	firefoxImageAccept158Major = 158
)

// Safari Accept values, from WebCore/loader/cache/CachedResourceRequest.cpp.
const (
	// safariDocumentAccept is the main resource Accept of every frame,
	// captured from Safari 26.0.1 and 27.
	safariDocumentAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

	// safariImageAccept is the image Accept WebKit builds: WebP, then AVIF,
	// JPEG XL, and HEIC, which Cocoa builds support, then video for animated
	// images, then the generic types. WebKit source verifies the
	// construction but not the runtime string, which assumes no additional
	// image types and working video decoding; no image request was
	// captured. It deliberately replaces fphttp v1's value, which omits
	// AVIF, JPEG XL, and HEIC and places video after the image types.
	safariImageAccept = "image/webp,image/avif,image/jxl,image/heic,image/heic-sequence,video/*;q=0.8,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
)

// Accept returns the Accept value the release sends for a request
// destination, given as a Sec-Fetch-Dest value such as "document", "image",
// or "empty"; "" is a top-level page load. It returns "" for an unknown
// destination.
func (e Entry) Accept(destination string) string {
	kind := parseDestination(destination)
	if kind == destinationUnknown {
		return ""
	}

	switch e.Family {
	case FamilyChromium:
		return e.chromiumAccept(kind)
	case FamilyFirefox:
		return e.firefoxAccept(kind)
	case FamilySafari:
		return safariAccept(kind)
	default:
		return ""
	}
}

// chromiumAccept returns Chromium's Accept. Frame navigations, including
// the content frames of object and embed elements, send the frame value;
// stylesheets and XSLT share one value; every other subresource and worker
// sends */*. Report requests were not traced and keep fphttp v1's */*.
//
// A WebSocket handshake carries no Accept: the network stack builds it
// without the renderer's or URLLoader's fetch fields
// (net/websockets/websocket_stream.cc).
func (e Entry) chromiumAccept(destination fetchDestination) string {
	if destination.chromiumNavigation() {
		return e.chromiumFrameAccept()
	}

	switch destination {
	case destinationWebSocket:
		return ""

	case destinationImage:
		if e.chromiumMajor() >= chromiumJXLMajor {
			return chromiumImageAccept155
		}

		return chromiumImageAccept108

	case destinationStyle, destinationXSLT:
		return acceptStylesheet

	default:
		return acceptAny
	}
}

// chromiumFrameAccept returns the Accept of a frame navigation. Only Chrome
// gets the signed exchange suffix; Edge and Brave keep fphttp v1's value
// without it, because their signed exchange default was not verified.
func (e Entry) chromiumFrameAccept() string {
	major := e.chromiumMajor()

	accept := chromiumFrameAccept108
	if major >= chromiumJXLMajor {
		accept = chromiumFrameAccept155
	}

	switch {
	case e.Browser != Chrome:
		return accept
	case major < chromiumSignedExchange110Major:
		return accept + chromiumSignedExchange108
	default:
		return accept + chromiumSignedExchange110
	}
}

// firefoxAccept returns Firefox's Accept. Destinations without a dedicated
// value in Firefox source, such as manifests, workers, and reports, keep
// fphttp v1's */*. A WebSocket handshake verifiably sends */*
// (ACCEPT_HEADER_ALL in nsHttpHandler::AddStandardRequestHeaders).
func (e Entry) firefoxAccept(destination fetchDestination) string {
	switch destination {
	case destinationDocument, destinationSubframe:
		return e.firefoxDocumentAccept()
	case destinationImage:
		return e.firefoxImageAccept()
	case destinationStyle:
		return acceptStylesheet
	case destinationFont:
		return firefoxFontAccept
	case destinationAudio:
		return firefoxAudioAccept
	case destinationVideo:
		return firefoxVideoAccept
	default:
		return acceptAny
	}
}

// firefoxDocumentAccept returns the document and iframe Accept. Firefox ESR
// 128 dropped image types in 128.7, ahead of its stable major, and the
// catalog's ESR 128 is 128.14.
func (e Entry) firefoxDocumentAccept() string {
	major := e.Major()

	switch {
	case major >= firefoxDocumentAccept132Major:
		return firefoxDocumentAccept132
	case e.Browser == FirefoxESR && major >= firefoxAccept128Major:
		return firefoxDocumentAccept132
	case major >= firefoxAccept128Major:
		return firefoxDocumentAccept128
	default:
		return firefoxDocumentAccept102
	}
}

// firefoxImageAccept returns the image Accept.
func (e Entry) firefoxImageAccept() string {
	major := e.Major()

	switch {
	case major >= firefoxImageAccept158Major:
		return firefoxImageAccept158
	case major >= firefoxAccept128Major:
		return firefoxImageAccept128
	default:
		return firefoxImageAccept102
	}
}

// safariAccept returns Safari's Accept, the same in Safari 26 and 27.
// Subframes load as main resources like the top-level document. Audio and
// video load through AVFoundation, which was not traced, and keep fphttp
// v1's */*. A WebSocket handshake, which CFNetwork builds, gets no Accept,
// because its fields were not verified.
func safariAccept(destination fetchDestination) string {
	switch destination {
	case destinationDocument, destinationSubframe:
		return safariDocumentAccept
	case destinationImage:
		return safariImageAccept
	case destinationStyle:
		return acceptStylesheet
	case destinationWebSocket:
		return ""
	default:
		return acceptAny
	}
}
