package browser

import (
	"strings"

	http "github.com/aarock1234/fphttp/v2"
)

func edgeSourceVariant(entry Descriptor) (Descriptor, bool) {
	major := strings.Split(entry.Version, ".")[0]
	if _, known := chromiumFamily(entry.Platform, major); !known {
		return Descriptor{}, false
	}

	variant := cloneDescriptor(entry)
	variant.Variant = "chromium-source-assumption"
	variant.ID = descriptorID(variant)
	variant.EngineVersion = major
	variant.Available = true
	variant.Coverage = assumedCoverage()
	variant.Sources = append(variant.Sources, Source{
		URL:  "https://learn.microsoft.com/en-us/deployedge/microsoft-edge-release-schedule",
		Note: "Microsoft documents equivalent Chromium major releases; this does not identify an exact engine patch or private Edge configuration.",
	})
	variant.Limitations = []string{
		"Explicit Chromium-major approximation, not an independently reproduced Edge build; Edge trials, enterprise settings and private changes can diverge.",
		"The exact Chromium engine build is unknown, so full-version client hints cannot be supplied from this descriptor.",
		"Regular header order is deterministic and conservative; complete Edge negotiation and connection-state behavior are not covered.",
	}
	if compareVersions(major, "119") < 0 {
		variant.Limitations = append(variant.Limitations,
			"The unreduced User-Agent needs a complete Chromium engine version; callers must provide an explicitly captured User-Agent.")
	}

	return variant, true
}

func safariCaptureVariant(entry Descriptor) (Descriptor, bool) {
	if entry.Version != "26.0" && entry.Version != "27.0" {
		return Descriptor{}, false
	}
	if entry.Platform == http.PlatformIPadOS ||
		(entry.Version == "26.0" && entry.Platform != http.PlatformMac) {
		return Descriptor{}, false
	}

	variant := cloneDescriptor(entry)
	variant.Variant = "existing-capture-family"
	variant.ID = descriptorID(variant)
	variant.Available = true
	variant.Coverage = assumedCoverage()
	variant.Sources = append(variant.Sources, Source{
		URL:  "https://github.com/aarock1234/fphttp/blob/main/profile_safari.go",
		Note: "Retained implementation from supplied Safari 26.0.1 macOS and Safari 27/iPhone 27.0.1 captures; the original capture artifact is not archived in this repository.",
	})
	variant.Limitations = []string{
		"Explicit existing-capture-family approximation; its original capture build is not this exact release and complete Apple networking source is unavailable.",
		"Safari 27 mobile needs an explicit UserAgentOSVersion or caller User-Agent because its frozen OS token is not established here.",
		"Session state, legacy advertised algorithms and OS-dependent networking behavior are only partially covered.",
	}

	return variant, true
}

func chromiumFamily(platform http.Platform, major string) (chromiumDefinition, bool) {
	var selected chromiumDefinition
	found := false
	for _, definition := range chromiumDefinitions {
		if definition.Platform != platform || strings.Split(definition.Version, ".")[0] != major {
			continue
		}
		if !found || compareVersions(definition.Version, selected.Version) > 0 {
			selected = definition
			found = true
		}
	}

	return selected, found
}
