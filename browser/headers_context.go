package browser

import (
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	http "github.com/aarock1234/fphttp"
)

func contextualHeaders(req *http.Request, p *Profile, metadata *RequestContext) (http.Header, error) {
	headers := make(http.Header)
	headers.Set("Accept", contextAccept(p, metadata))
	if metadata.AcceptLanguage != "" {
		headers.Set("Accept-Language", metadata.AcceptLanguage)
	} else if len(metadata.Languages) > 0 {
		language, err := contextLanguages(p, metadata.Languages)
		if err != nil {
			return nil, err
		}
		headers.Set("Accept-Language", language)
	}
	if metadata.IsNavigation() {
		headers.Set("Upgrade-Insecure-Requests", "1")
	}
	if headerTrustworthy(req.URL) {
		headers.Set("Sec-Fetch-Site", fetchSite(req, metadata))
		mode := metadata.Mode
		if mode == "" {
			mode = ModeCORS
			if metadata.IsNavigation() {
				mode = ModeNavigate
			}
		}
		headers.Set("Sec-Fetch-Mode", string(mode))
		destination := metadata.Destination
		if destination == "" {
			destination = "empty"
			if metadata.IsNavigation() {
				destination = "document"
			}
		}
		headers.Set("Sec-Fetch-Dest", destination)
		if metadata.IsNavigation() && metadata.UserActivation {
			headers.Set("Sec-Fetch-User", "?1")
		}
	}
	referrer, referrerPolicy := contextRequestReferrer(req, metadata)
	if metadata.Initiator != nil && needsOrigin(req, metadata) {
		headers.Set("Origin", contextOrigin(req, metadata, referrerPolicy))
	}
	if referrer != "" {
		headers.Set("Referer", referrer)
	}
	if metadata.CacheMode != CacheDefault {
		switch metadata.CacheMode {
		case CacheReload:
			headers.Set("Cache-Control", "max-age=0")
		case CacheNoCache:
			headers.Set("Cache-Control", "no-cache")
			headers.Set("Pragma", "no-cache")
		}
	}

	return headers, nil
}

func contextAccept(p *Profile, metadata *RequestContext) string {
	if metadata.Kind == Fetch {
		return "*/*"
	}
	major, _ := identityMajor(p.descriptor.Version)
	family := p.descriptor.Browser
	if p.descriptor.Platform == http.PlatformIOS || p.descriptor.Platform == http.PlatformIPadOS {
		family = http.BrowserSafari
	}
	if metadata.IsNavigation() {
		switch family {
		case http.BrowserFirefox:
			if major >= 132 {
				return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
			}
			if major >= 128 {
				return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8"
			}

			return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
		case http.BrowserSafari:
			return "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
		default:
			accept := "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
			if p.descriptor.Browser == http.BrowserChrome && chromiumClientHints(p) {
				accept += ",application/signed-exchange;v=b3;q=0.7"
			}

			return accept
		}
	}

	switch metadata.Destination {
	case "style":
		return "text/css,*/*;q=0.1"
	case "image":
		switch family {
		case http.BrowserFirefox:
			if major >= 158 {
				return "image/avif,image/jxl,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
			}
			if major >= 128 {
				return "image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5"
			}

			return "image/avif,image/webp,*/*"
		case http.BrowserSafari:
			return "image/webp,image/png,image/svg+xml,image/*;q=0.8,video/*;q=0.8,*/*;q=0.5"
		default:
			return "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"
		}
	case "audio":
		if family == http.BrowserFirefox {
			return "audio/webm,audio/ogg,audio/wav,audio/*;q=0.9,application/ogg;q=0.7,video/*;q=0.6,*/*;q=0.5"
		}
	case "video":
		if family == http.BrowserFirefox {
			return "video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5"
		}
	}

	return "*/*"
}

func contextLanguages(p *Profile, languages []string) (string, error) {
	if len(languages) == 1 {
		return languages[0], nil
	}
	appleEngine := p.descriptor.Platform == http.PlatformIOS || p.descriptor.Platform == http.PlatformIPadOS
	if p.descriptor.Browser == http.BrowserSafari || appleEngine {
		return "", errors.New("browser: supply an exact AcceptLanguage for this Apple browser")
	}
	values := make([]string, len(languages))
	for i, language := range languages {
		values[i] = language
		if i == 0 {
			continue
		}
		quality := max(1, 10-i)
		if p.descriptor.Browser == http.BrowserFirefox {
			quality = max(1, ((len(languages)-i)*10+len(languages)/2)/len(languages))
		}
		if quality == 10 {
			values[i] += ";q=1.0"
		} else {
			values[i] += ";q=0." + strconv.Itoa(quality)
		}
	}

	return strings.Join(values, ","), nil
}

func fetchSite(req *http.Request, metadata *RequestContext) string {
	if metadata.Initiator == nil {
		return "none"
	}
	relation := headerSiteRelation(metadata.Initiator, req.URL)
	for response := req.Response; response != nil && response.Request != nil; response = response.Request.Response {
		relation = max(relation, headerSiteRelation(metadata.Initiator, response.Request.URL))
	}
	switch relation {
	case 0:
		return "same-origin"
	case 1:
		return "same-site"
	default:
		return "cross-site"
	}
}

func headerSiteRelation(a, b *url.URL) int {
	if sameHeaderOrigin(a, b) {
		return 0
	}
	if a == nil || b == nil || a.Scheme != b.Scheme {
		return 2
	}
	hostA := strings.ToLower(a.Hostname())
	hostB := strings.ToLower(b.Hostname())
	if hostA == hostB && hostA != "" {
		return 1
	}
	siteA, errA := publicsuffix.EffectiveTLDPlusOne(hostA)
	siteB, errB := publicsuffix.EffectiveTLDPlusOne(hostB)
	if errA == nil && errB == nil && siteA == siteB {
		return 1
	}

	return 2
}

func needsOrigin(req *http.Request, metadata *RequestContext) bool {
	if req.Method != "" && req.Method != http.MethodGet && req.Method != http.MethodHead {
		return true
	}
	mode := metadata.Mode
	if mode == "" && metadata.Kind == Fetch {
		mode = ModeCORS
	}

	return mode == ModeCORS && (!sameHeaderOrigin(metadata.Initiator, req.URL) || redirectTaintsOrigin(req, metadata.Initiator))
}

func contextOrigin(req *http.Request, metadata *RequestContext, policy ReferrerPolicy) string {
	if redirectTaintsOrigin(req, metadata.Initiator) {
		return "null"
	}
	mode := metadata.Mode
	if mode == "" && metadata.Kind == Fetch {
		mode = ModeCORS
	}
	if mode != ModeCORS {
		switch policy {
		case ReferrerNoReferrer:
			return "null"
		case ReferrerDefault, ReferrerNoReferrerWhenDowngrade, ReferrerStrictOrigin, ReferrerStrictOriginWhenCrossOrigin:
			if metadata.Initiator.Scheme == "https" && req.URL.Scheme != "https" {
				return "null"
			}
		case ReferrerSameOrigin:
			if !sameHeaderOrigin(metadata.Initiator, req.URL) {
				return "null"
			}
		}
	}

	return headerOrigin(metadata.Initiator)
}

func redirectTaintsOrigin(req *http.Request, initiator *url.URL) bool {
	chain := []*url.URL{req.URL}
	for response := req.Response; response != nil && response.Request != nil; response = response.Request.Response {
		chain = append(chain, response.Request.URL)
	}
	slices.Reverse(chain)
	for i := 1; i < len(chain); i++ {
		if !sameHeaderOrigin(chain[i-1], chain[i]) && !sameHeaderOrigin(initiator, chain[i-1]) {
			return true
		}
	}

	return false
}

// Only independently recorded fetch layouts override a profile's layout.
// Other contexts retain its recorded order and caller overrides; the catalog
// describes missing request-layout evidence rather than claiming an alias.
func applyContextLayout(req *http.Request, p *Profile, metadata *RequestContext) {
	if metadata.Kind != Fetch {
		return
	}
	var layout *http.Fingerprint
	engineMajor, _ := identityMajor(p.descriptor.EngineVersion)
	productMajor, _ := identityMajor(p.descriptor.Version)
	switch {
	case p.descriptor.Browser == http.BrowserChrome && p.descriptor.Platform == http.PlatformWindows && engineMajor == 148:
		layout = http.Chrome148Fetch()
	case p.descriptor.Browser == http.BrowserChrome && p.descriptor.Platform == http.PlatformMac && engineMajor == 154:
		layout = http.Chrome154MacHTTP2Fetch()
	case p.descriptor.Browser == http.BrowserSafari && p.descriptor.Platform == http.PlatformMac && productMajor == 27:
		layout = http.Safari27Fetch()
	case p.descriptor.Browser == http.BrowserSafari && p.descriptor.Platform == http.PlatformIOS && productMajor == 27:
		layout = http.SafariIOS27Fetch()
	}
	if layout == nil {
		return
	}
	if req.HeaderOrder == nil {
		req.HeaderOrder = slices.Clone(layout.HeaderOrder)
	}
	if req.H2Priority == nil {
		priority := layout.H2.HeaderPriority
		req.H2Priority = &priority
	}
}

// Chromium emits extensible priority fields in its HTTP/2 serializer. Source
// defaults are build-specific, and resource priority depends on page state.
func applyContextPriority(req *http.Request, p *Profile, metadata *RequestContext) {
	if !chromiumClientHints(p) || metadata.Kind != Navigation && metadata.Kind != Fetch {
		return
	}
	definition, found := chromiumDefinitionForDescriptor(p.descriptor)
	if !found {
		return
	}
	if req.H2Priority == nil {
		priority := p.fingerprint.H2.HeaderPriority
		if priority.Enabled {
			// Blink's ordinary raw fetch priority maps to net::MEDIUM, whose
			// HTTP/2 effective weight is 220; the wire representation is 219.
			if metadata.Kind == Fetch {
				priority.Weight = 219
			}
			req.H2Priority = &priority
		}
	}
	if req.H2PriorityHeader != "" || !definition.PriorityHeader {
		return
	}
	if present, _ := requestHeader(req.Header, "Priority"); present {
		return
	}

	switch metadata.Kind {
	case Navigation:
		req.H2PriorityHeader = "u=0, i"
	case Fetch:
		req.H2PriorityHeader = "u=1, i"
	}
}
