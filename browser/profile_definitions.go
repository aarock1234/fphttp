package browser

import (
	"fmt"
	"strings"

	http "github.com/aarock1234/fphttp"
)

func appendProfileDefinitions(entries []Descriptor) []Descriptor {
	var variants []Descriptor
	for index := range entries {
		entry := &entries[index]
		if entry.Browser != http.BrowserChrome {
			continue
		}
		definition, ok := chromiumDefinitions[string(entry.Platform)+"/"+entry.Version]
		if !ok {
			continue
		}
		entry.Available = true
		entry.Coverage = sourceCoverage()
		if !definition.H2Verified {
			entry.Coverage.HTTP2 = EvidenceAssumed
		}
		entry.Sources = append(entry.Sources, definition.Sources...)
		entry.Limitations = []string{
			"Compiled source defaults; Chrome field trials, enterprise policies, CPU cipher preferences, and component updates can change the observed fingerprint.",
			"TLS parameters use a reviewed uTLS family; certificate validation and trust-anchor response-driven retry behavior are not identical to Chrome.",
			"Initial H2 frames are modeled; complete browser stream scheduling, HPACK history, and subsequent connection behavior are not reproduced.",
			"Regular headers use a deterministic conservative order; exact browser insertion order is not established for this build and request context.",
			"Per-profile caches do not establish browser-like resumption: the parameter family may lack a compatible PSK offer; real ECH and trust-anchor response-driven retries require additional state.",
		}
		if !definition.H2Verified {
			entry.Limitations = append(entry.Limitations,
				"The complete tagged H2 default source shape did not match the recognized model; initial settings and flow therefore remain a partial family approximation.")
		}
		if len(definition.TrustAnchorIDs) > 0 {
			entry.Limitations = append(entry.Limitations,
				"Trust-anchor IDs use deterministic bundled-ID ordering as an approximation of Chrome's unordered process-specific set and component state.")
		}
		if entry.Platform == http.PlatformAndroid && strings.HasPrefix(entry.Version, "109.") {
			entry.Limitations = append(entry.Limitations,
				"The unreduced Android User-Agent is not established for this build; callers must provide an explicitly captured User-Agent.")
		}
		if definition.SettingsGREASE {
			variant := cloneDescriptor(*entry)
			variant.Variant = "h2-settings-grease"
			variant.ID = descriptorID(variant)
			variant.Limitations = append(variant.Limitations,
				"Explicit HTTP/2 SETTINGS GREASE configuration; its presence is not inferred from the product version or platform.")
			variants = append(variants, variant)
		}
	}

	entries = append(entries, variants...)

	return appendOtherDefinitions(entries)
}

func fingerprintFor(descriptor Descriptor) (*http.Fingerprint, error) {
	if descriptor.Browser == http.BrowserChrome && (descriptor.Variant == "source-default" || descriptor.Variant == "h2-settings-grease") {
		definition, ok := chromiumDefinitions[string(descriptor.Platform)+"/"+descriptor.Version]
		if ok {
			fingerprint := chromiumFingerprint(definition)
			if descriptor.Variant == "h2-settings-grease" {
				configureSettingsGREASE(fingerprint)
			}

			return fingerprint, nil
		}
	}
	if fingerprint := otherFingerprint(descriptor); fingerprint != nil {
		return fingerprint, nil
	}

	return nil, fmt.Errorf("%w: no implementation for %s", ErrUnavailable, descriptor.ID)
}

func descriptorID(descriptor Descriptor) string {
	return strings.Join([]string{
		string(descriptor.Browser),
		string(descriptor.Platform),
		descriptor.Version,
		descriptor.Channel,
		descriptor.Variant,
		descriptor.OSBuild,
		descriptor.Device,
	}, "/")
}
