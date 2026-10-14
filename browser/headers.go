package browser

import (
	"errors"
	"fmt"
	"strings"

	http "github.com/aarock1234/fphttp"
)

func prepareHeaders(req *http.Request, p *Profile, metadata *RequestContext, acceptedHints []string, disabled bool) (*http.Request, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("browser: request and URL must not be nil")
	}
	if err := metadata.validate(); err != nil {
		return nil, err
	}
	prepared := req.Clone(req.Context())
	if prepared.Header == nil {
		prepared.Header = make(http.Header)
	}
	if err := normalizeManagedHeaders(prepared.Header); err != nil {
		return nil, err
	}
	if disabled {
		if present, _ := requestHeader(prepared.Header, "User-Agent"); !present {
			prepared.Header["User-Agent"] = nil
		}

		return prepared, nil
	}

	var device *DeviceMetadata
	if metadata != nil {
		device = metadata.Device
	}
	advancedEncoding := advancedEncodingDestination(p, req.URL)
	defaults, err := identityHeaders(p, device, advancedEncoding)
	if err != nil {
		present, _ := requestHeader(prepared.Header, "User-Agent")
		if !present {
			return nil, err
		}
		// A complete caller UA can supply an identity whose OS token is not
		// in the catalog. Do not invent hints to accompany that override.
		defaults = make(http.Header)
		defaults.Set("Accept-Encoding", profileEncodings(p, advancedEncoding))
	}
	for name, values := range defaults {
		if strings.HasPrefix(strings.ToLower(name), "sec-ch-") {
			if !headerTrustworthy(req.URL) || !clientHintPermitted(metadata, req.URL, strings.ToLower(name)) {
				continue
			}
		}
		setMissingHeader(prepared.Header, name, values[0])
	}
	applyIdentityHeaderCase(prepared, p)
	if chromiumClientHints(p) && !prepared.Close {
		setMissingHeader(prepared.Header, "Connection", "keep-alive")
	}
	if rangePresent, _ := requestHeader(prepared.Header, "Range"); rangePresent && chromiumClientHints(p) {
		if present, _ := requestHeader(req.Header, "Accept-Encoding"); !present {
			prepared.Header.Set("Accept-Encoding", "identity")
		}
	}
	if metadata == nil {
		return prepared, nil
	}

	contextHeaders, err := contextualHeaders(prepared, p, metadata)
	if err != nil {
		return nil, err
	}
	for name, values := range contextHeaders {
		setMissingHeader(prepared.Header, name, values[0])
	}
	if len(acceptedHints) > 0 {
		values, err := clientHintValues(p, metadata)
		if err != nil {
			return nil, err
		}
		for _, name := range allowedClientHints(p, prepared, metadata, acceptedHints) {
			canonical := http.CanonicalHeaderKey(name)
			if value, available := values[canonical]; available && len(value) > 0 {
				setMissingHeader(prepared.Header, canonical, value[0])
			}
		}
	}
	applyContextLayout(prepared, p, metadata)
	applyContextPriority(prepared, p, metadata)

	return prepared, nil
}

func requestHeader(headers http.Header, name string) (bool, []string) {
	for key, values := range headers {
		if strings.EqualFold(key, name) {
			return true, values
		}
	}

	return false, nil
}

func headerSuppressed(values []string) bool {
	return len(values) == 0 || len(values) == 1 && values[0] == ""
}

func setMissingHeader(headers http.Header, name, value string) {
	if present, _ := requestHeader(headers, name); present {
		return
	}
	headers.Set(name, value)
}

// Chromium preserves the lowercase names supplied by its client hint mapper
// when serializing HTTP/1.1. HTTP/2 field names are already lowercase.
func applyIdentityHeaderCase(req *http.Request, p *Profile) {
	if req.H1HeaderCase != nil || !chromiumClientHints(p) {
		return
	}

	req.H1HeaderCase = make(map[string]string)
	for _, name := range []string{
		"sec-ch-ua",
		"sec-ch-ua-mobile",
		"sec-ch-ua-platform",
		"sec-ch-ua-arch",
		"sec-ch-ua-bitness",
		"sec-ch-ua-platform-version",
		"sec-ch-ua-model",
		"sec-ch-ua-wow64",
		"sec-ch-ua-full-version",
		"sec-ch-ua-full-version-list",
		"sec-ch-ua-form-factors",
	} {
		req.H1HeaderCase[http.CanonicalHeaderKey(name)] = name
	}
}

func normalizeManagedHeaders(headers http.Header) error {
	seen := make(map[string]string)
	for name := range headers {
		if !managedHeader(name) {
			continue
		}
		lower := strings.ToLower(name)
		if previous, duplicate := seen[lower]; duplicate {
			return fmt.Errorf("browser: duplicate managed header keys %q and %q", previous, name)
		}
		seen[lower] = name
	}
	for _, original := range seen {
		values := headers[original]
		canonical := http.CanonicalHeaderKey(original)
		if original != canonical {
			delete(headers, original)
		}
		if headerSuppressed(values) {
			values = nil
		}
		headers[canonical] = values
	}

	return nil
}

func managedHeader(name string) bool {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "sec-ch-") || strings.HasPrefix(name, "sec-fetch-") {
		return true
	}

	switch name {
	case "user-agent", "accept-encoding", "accept", "accept-language", "connection", "proxy-connection", "origin",
		"referer", "upgrade-insecure-requests", "cache-control", "pragma", "priority":
		return true
	default:
		return false
	}
}
