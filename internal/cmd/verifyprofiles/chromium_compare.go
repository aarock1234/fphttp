package main

import (
	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// compareChromium lists every field where the catalog's Chromium wire
// differs from the wire derived from source.
func compareChromium(wire *catalog.Wire, source chromiumFeatures) []difference {
	features := wire.Chromium
	if features == nil {
		return []difference{
			{
				field:   "engine",
				catalog: "not chromium",
				source:  "chromium",
			},
		}
	}

	catalogECH := features.Hello != catalog.ChromiumHelloClassical
	catalogAnchors := describeTrustAnchors(features.TrustAnchorIDs)
	sourceAnchors := describeTrustAnchors(source.trustAnchorIDs)

	var diffs []difference

	diffs = differ(diffs, "hello", helloName(features.Hello), helloName(source.hello))
	diffs = differ(diffs, "ech grease", catalogECH, source.ech)
	diffs = differ(diffs, "extension shuffle", features.Shuffle, source.shuffle)
	diffs = differ(diffs, "new alps code point", features.NewALPS, source.newALPS)
	diffs = differ(diffs, "ml-dsa signature algorithms", features.MLDSA, source.mldsa)
	diffs = differ(diffs, "signature algorithm grease", features.SignatureGREASE, source.signatureGREASE)
	diffs = differ(diffs, "trust anchor ids", catalogAnchors, sourceAnchors)
	diffs = differ(diffs, "priority header", features.PriorityHeader, source.priorityHeader)
	diffs = differ(diffs, "max concurrent streams", features.MaxConcurrentStreams, source.maxConcurrentStreams)

	settings := []sourceSetting{
		{
			id:    fingerprint.SettingHeaderTableSize,
			value: source.http2.headerTableSize,
		},
		{
			id:    fingerprint.SettingEnablePush,
			value: source.http2.enablePush,
		},
		{
			id:    fingerprint.SettingInitialWindowSize,
			value: source.http2.initialWindowSize,
		},
		{
			id:    fingerprint.SettingMaxHeaderListSize,
			value: source.http2.maxHeaderListSize,
		},
	}

	return differSettings(diffs, wire.HTTP2, settings, source.http2.connectionFlow)
}
