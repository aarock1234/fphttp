package browser

import (
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/net/idna"

	http "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/internal/httpsfv"
)

func parseClientHints(values []string) []string {
	hints, _ := parseClientHintList(values)

	return hints
}

// An empty valid list clears opt-in state; malformed syntax does not.
func parseClientHintList(values []string) ([]string, bool) {
	value := strings.TrimSpace(strings.Join(values, ","))
	if value == "" {
		return nil, true
	}

	var hints []string
	validMembers := true
	validSyntax := httpsfv.ParseList(value, func(member, _ string) {
		name, ok := httpsfv.ParseToken(member)
		if !ok {
			validMembers = false
			return
		}
		name = strings.ToLower(name)
		if supportedClientHint(name) && !slices.Contains(hints, name) {
			hints = append(hints, name)
		}
	})
	if !validSyntax || !validMembers {
		return nil, false
	}

	return hints, true
}

func allowedClientHints(p *Profile, req *http.Request, metadata *RequestContext, requested []string) []string {
	if !chromiumClientHints(p) || req == nil || !headerTrustworthy(req.URL) {
		return nil
	}
	values, err := clientHintValues(p, metadata)
	if err != nil {
		return nil
	}

	var allowed []string
	for _, name := range requested {
		name = strings.ToLower(name)
		if !supportedClientHint(name) || !clientHintPermitted(metadata, req.URL, name) {
			continue
		}
		present, explicit := requestHeader(req.Header, name)
		if present && headerSuppressed(explicit) {
			continue
		}
		if _, available := values[http.CanonicalHeaderKey(name)]; !available && !present {
			continue
		}
		if !slices.Contains(allowed, name) {
			allowed = append(allowed, name)
		}
	}

	return allowed
}

func clientHintValues(p *Profile, metadata *RequestContext) (http.Header, error) {
	var device *DeviceMetadata
	if metadata != nil {
		device = metadata.Device
	}
	values, err := basicClientHintValues(p, device)
	if err != nil {
		return nil, err
	}
	if metadata == nil || !chromiumClientHints(p) {
		return values, nil
	}

	if completeEngineVersion(p.descriptor.EngineVersion) {
		fullList, err := chromiumBrands(p, true)
		if err != nil {
			return nil, err
		}
		values.Set("Sec-Ch-Ua-Full-Version-List", fullList)
		fullVersion := p.descriptor.EngineVersion
		if p.descriptor.Browser == http.BrowserEdge {
			fullVersion = p.descriptor.Version
		}
		if err := setHintString(values, "Sec-Ch-Ua-Full-Version", fullVersion); err != nil {
			return nil, err
		}
	}
	if p.descriptor.Platform == http.PlatformLinux {
		values.Set("Sec-Ch-Ua-Platform-Version", `""`)
	}
	if p.descriptor.Platform != http.PlatformAndroid || p.descriptor.Browser == http.BrowserBrave {
		values.Set("Sec-Ch-Ua-Model", `""`)
	}
	if p.descriptor.Platform != http.PlatformWindows {
		values.Set("Sec-Ch-Ua-Wow64", "?0")
	}
	engineMajor, _ := identityMajor(p.descriptor.EngineVersion)
	if engineMajor >= 123 {
		formFactor := "Desktop"
		if profileMobile(p, device) {
			formFactor = "Mobile"
		}
		values.Set("Sec-Ch-Ua-Form-Factors", `"`+formFactor+`"`)
	}
	if device == nil {
		return values, nil
	}

	attributes := []struct {
		name  string
		value *string
	}{
		{
			name:  "Sec-Ch-Ua-Arch",
			value: device.Architecture,
		},
		{
			name:  "Sec-Ch-Ua-Bitness",
			value: device.Bitness,
		},
		{
			name:  "Sec-Ch-Ua-Platform-Version",
			value: device.PlatformVersion,
		},
		{
			name:  "Sec-Ch-Ua-Model",
			value: device.Model,
		},
	}
	for _, attribute := range attributes {
		if attribute.value != nil {
			if err := setHintString(values, attribute.name, *attribute.value); err != nil {
				return nil, err
			}
		}
	}
	if device.WoW64 != nil {
		values.Set("Sec-Ch-Ua-Wow64", structuredBoolean(*device.WoW64))
	}
	if device.FormFactors != nil && engineMajor >= 123 {
		encoded := make([]string, 0, len(device.FormFactors))
		for _, formFactor := range device.FormFactors {
			value, err := structuredString(formFactor)
			if err != nil {
				return nil, err
			}
			encoded = append(encoded, value)
		}
		values.Set("Sec-Ch-Ua-Form-Factors", strings.Join(encoded, ", "))
	}

	return values, nil
}

func setHintString(headers http.Header, name, value string) error {
	encoded, err := structuredString(value)
	if err != nil {
		return err
	}
	headers.Set(name, encoded)

	return nil
}

func supportedClientHint(name string) bool {
	switch name {
	case "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-arch",
		"sec-ch-ua-bitness", "sec-ch-ua-platform-version", "sec-ch-ua-model",
		"sec-ch-ua-wow64", "sec-ch-ua-full-version", "sec-ch-ua-full-version-list",
		"sec-ch-ua-form-factors":
		return true
	default:
		return false
	}
}

func lowEntropyClientHint(name string) bool {
	return name == "sec-ch-ua" || name == "sec-ch-ua-mobile" || name == "sec-ch-ua-platform"
}

func clientHintPermitted(metadata *RequestContext, destination *url.URL, name string) bool {
	if metadata == nil {
		return lowEntropyClientHint(name)
	}
	var origins []string
	explicit := false
	for field, permitted := range metadata.ClientHintPermissions {
		if strings.EqualFold(field, name) {
			origins = permitted
			explicit = true
			break
		}
	}
	policyOrigin := metadata.TopLevelOrigin
	if policyOrigin == nil {
		policyOrigin = metadata.Initiator
	}
	if explicit {
		for _, origin := range origins {
			if origin == "*" || origin == "self" && sameHeaderOrigin(policyOrigin, destination) {
				return true
			}
			permitted, err := url.Parse(origin)
			if err == nil && sameHeaderOrigin(permitted, destination) {
				return true
			}
		}

		return false
	}
	if lowEntropyClientHint(name) || metadata.IsNavigation() {
		return true
	}

	return sameHeaderOrigin(policyOrigin, destination)
}

func headerTrustworthy(destination *url.URL) bool {
	if destination == nil {
		return false
	}

	return destination.Scheme == "https" || destination.Scheme == "http" && headerLocalhost(destination.Hostname())
}

func headerLocalhost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	address, err := netip.ParseAddr(host)

	return err == nil && address.IsLoopback()
}

func headerOrigin(value *url.URL) string {
	if value == nil || value.Hostname() == "" || value.Scheme != "http" && value.Scheme != "https" {
		return ""
	}
	host := strings.ToLower(value.Hostname())
	if address, err := netip.ParseAddr(host); err == nil {
		host = address.String()
	} else {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return ""
		}
		host = ascii
	}
	port := value.Port()
	if port == "" || value.Scheme == "http" && port == "80" || value.Scheme == "https" && port == "443" {
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}

		return value.Scheme + "://" + host
	}

	return value.Scheme + "://" + net.JoinHostPort(host, port)
}

func sameHeaderOrigin(a, b *url.URL) bool {
	origin := headerOrigin(a)

	return origin != "" && origin == headerOrigin(b)
}
