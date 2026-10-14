package http

import "github.com/aarock1234/fphttp/v2/internal/catalog"

// clientHints adds the User-Agent client hints of a Chromium release, which
// go only to potentially trustworthy URLs.
//
// The low-entropy hints, Sec-CH-UA, Sec-CH-UA-Mobile, and
// Sec-CH-UA-Platform, go on every such request. A high-entropy hint goes
// only when the origin of the request URL asked for it with Accept-CH, the
// request may carry it (see highEntropyHintsPermitted), and the release has
// a value for it; the catalog leaves values empty where the browser sends
// none or the default is unverified.
//
// A WebSocket handshake carries no client hints: Chromium adds them in
// Blink's fetch context and the browser's navigation code, and neither
// builds a handshake.
func (g *fieldGenerator) clientHints() {
	values := g.hintValues
	if values == nil || !g.trustworthy() || g.webSocket() {
		return
	}

	g.addMissing("Sec-Ch-Ua", values.Brands)
	g.addMissing("Sec-Ch-Ua-Mobile", values.Mobile)
	g.addMissing("Sec-Ch-Ua-Platform", values.Platform)

	if !highEntropyHintsPermitted(g.request) {
		return
	}

	for _, name := range g.hintStore.hints(requestOrigin(g.request.URL)) {
		field := CanonicalHeaderKey(name)
		g.addMissing(field, highEntropyHintValue(values, field))
	}
}

// highEntropyHintsPermitted reports whether the request may carry the
// high-entropy hints its origin asked for, under the default permissions
// policy of User-Agent client hints: a top-level page load always may, and
// any other request only when it stays on its initiator's origin.
func highEntropyHintsPermitted(request *Request) bool {
	if request.Destination.topLevel() {
		return true
	}

	return sameOrigin(request.Initiator, request.URL)
}

// highEntropyHintValue returns the value of the high-entropy hint with the
// canonical field name, or "" for any other field and for a hint the
// release does not send.
func highEntropyHintValue(values *catalog.ClientHints, field string) string {
	switch field {
	case "Sec-Ch-Ua-Full-Version":
		return values.FullVersion
	case "Sec-Ch-Ua-Full-Version-List":
		return values.FullVersionList
	case "Sec-Ch-Ua-Arch":
		return values.Arch
	case "Sec-Ch-Ua-Bitness":
		return values.Bitness
	case "Sec-Ch-Ua-Model":
		return values.Model
	case "Sec-Ch-Ua-Platform-Version":
		return values.PlatformVersion
	case "Sec-Ch-Ua-Wow64":
		return values.WoW64
	case "Sec-Ch-Ua-Form-Factors":
		return values.FormFactors
	default:
		return ""
	}
}
