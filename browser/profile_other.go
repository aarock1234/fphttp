package browser

import (
	"slices"
	"strings"

	http "github.com/aarock1234/fphttp/v2"
)

func appendOtherDefinitions(entries []Descriptor) []Descriptor {
	var variants []Descriptor
	for index := range entries {
		entry := &entries[index]
		var variant Descriptor
		var available bool

		switch entry.Browser {
		case http.BrowserBrave:
			configureBraveEntry(entry)
		case http.BrowserFirefox:
			variant, available = configureFirefoxEntry(entry)
		case http.BrowserEdge:
			variant, available = edgeSourceVariant(*entry)
		case http.BrowserSafari:
			variant, available = safariCaptureVariant(*entry)
		}
		if available {
			variants = append(variants, variant)
		}
	}

	return append(entries, variants...)
}

func configureBraveEntry(entry *Descriptor) {
	definition, found := braveDefinitions[string(entry.Platform)+"/"+entry.Version]
	if !found {
		return
	}

	entry.EngineVersion = definition.EngineVersion
	entry.Available = true
	entry.Coverage = sourceCoverage()
	if !definition.Chromium.H2Verified {
		entry.Coverage.HTTP2 = EvidenceAssumed
	}
	entry.Sources = append(entry.Sources, definition.Chromium.Sources...)
	entry.Sources = append(entry.Sources, definition.Sources...)
	entry.Limitations = []string{
		"Brave's exact engine pin and obtained feature overrides are modeled; complete downstream configuration, runtime privacy settings and every patch remain partially covered.",
		"Regular header ordering is deterministic and conservative; PSK offers, real ECH, trust-anchor retries and negotiated capabilities are not fully browser-equivalent.",
	}
}

func configureFirefoxEntry(entry *Descriptor) (Descriptor, bool) {
	definition, found := firefoxDefinitions[firefoxDefinitionKey(entry.Platform, entry.Channel, entry.Version)]
	if !found {
		return Descriptor{}, false
	}

	entry.Available = true
	entry.Coverage = sourceCoverage()
	entry.Sources = append(entry.Sources, definition.Sources...)
	entry.Limitations = []string{
		"NSS preference defaults select a uTLS parameter family; complete NSS serialization and platform cipher preferences are not reproduced.",
		"Delegated credentials, record-size enforcement and FFDHE negotiation remain incomplete; session resumption and real ECH need additional state.",
		"Regular headers use a deterministic conservative order, rather than a claimed exact browser insertion order.",
		"Initial HTTP/2 preferences select settings and flow values; complete frame initialization, priority scheduling and HPACK history remain partially covered.",
	}
	if !definition.AllowPush {
		return Descriptor{}, false
	}

	entry.Available = false
	entry.Coverage.HTTP2 = EvidenceSourceDerived
	entry.Limitations = append(entry.Limitations,
		"This release allows HTTP/2 server push by default; the transport cannot honor that browser capability.")

	variant := cloneDescriptor(*entry)
	variant.Variant = "push-disabled"
	variant.ID = descriptorID(variant)
	variant.Available = true
	variant.Coverage.HTTP2 = EvidenceAssumed
	variant.Limitations = append(variant.Limitations,
		"Explicit push-disabled configuration advertises ENABLE_PUSH=0 and the source-compatible pushed-stream limit; it does not reproduce the historical default.")

	return variant, true
}

func otherFingerprint(descriptor Descriptor) *http.Fingerprint {
	switch descriptor.Browser {
	case http.BrowserBrave:
		definition, found := braveDefinitions[string(descriptor.Platform)+"/"+descriptor.Version]
		if found {
			return chromiumFingerprint(definition.Chromium)
		}
	case http.BrowserFirefox:
		definition, found := firefoxDefinitions[firefoxDefinitionKey(descriptor.Platform, descriptor.Channel, descriptor.Version)]
		if found {
			return firefoxFingerprint(definition)
		}
	case http.BrowserEdge:
		if descriptor.Variant == "chromium-source-assumption" {
			definition, found := chromiumFamily(descriptor.Platform, descriptor.EngineVersion)
			if found {
				return chromiumFingerprint(definition)
			}
		}
	case http.BrowserSafari:
		if descriptor.Variant == "existing-capture-family" {
			fingerprint := http.Safari26()
			if strings.HasPrefix(descriptor.Version, "27.") {
				if descriptor.Platform == http.PlatformMac {
					fingerprint = http.Safari27()
				} else {
					fingerprint = http.SafariIOS27()
				}
			}
			fingerprint.HeaderOrder = slices.Clone(fingerprint.HeaderOrder)

			return fingerprint
		}
	}

	return nil
}
