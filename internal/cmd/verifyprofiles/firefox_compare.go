package main

import (
	"fmt"
	"slices"
	"strings"

	utls "github.com/refraction-networking/utls"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// compareFirefox lists every field where the catalog's Firefox wire differs
// from the wire derived from source.
//
// The catalog models releases with the legacy priority tree as sending
// ENABLE_PUSH 0 and MAX_CONCURRENT_STREAMS 0, because the transport cannot
// accept server push; those releases really allowed push. So a legacy-tree
// wire must match a source that allows push, and the push settings are
// compared only for releases that disallow it.
func compareFirefox(wire *catalog.Wire, source firefoxFeatures) []difference {
	features := wire.Firefox
	if features == nil {
		return []difference{
			{
				field:   "engine",
				catalog: "not firefox",
				source:  "firefox",
			},
		}
	}

	catalogPostQuantum := postQuantumNone
	if features.MLKEM {
		catalogPostQuantum = postQuantumMLKEM
	}

	catalogCiphers := describeCiphers(features.DisabledCiphers)
	sourceCiphers := describeCiphers(source.disabledCiphers)
	catalogCompression := describeCompression(features.CertCompression)
	sourceCompression := describeCompression(source.certCompression)

	var diffs []difference

	diffs = differ(diffs, "ech grease", features.ECH, source.ech)
	diffs = differ(diffs, "post-quantum key share", catalogPostQuantum, source.postQuantum)
	diffs = differ(diffs, "signed certificate timestamps", features.SCT, source.sct)
	diffs = differ(diffs, "ffdhe groups", features.FFDHE, source.ffdhe)
	diffs = differ(diffs, "ml-dsa signature algorithms", false, source.mldsa)
	diffs = differ(diffs, "disabled cipher suites", catalogCiphers, sourceCiphers)
	diffs = differ(diffs, "certificate compression", catalogCompression, sourceCompression)
	diffs = differ(diffs, "legacy priority tree", features.LegacyTree, source.legacyTree)
	diffs = differ(diffs, "no rfc 7540 priorities", features.NoRFC7540Priorities, source.noRFC7540Priorities)
	diffs = differ(diffs, "server push allowed", features.LegacyTree, source.allowPush)

	if !source.allowPush {
		diffs = differ(diffs, "max concurrent streams sent", features.LegacyTree, source.pushMaxConcurrent)
	}

	settings := []sourceSetting{
		{
			id:    fingerprint.SettingHeaderTableSize,
			value: source.headerTableSize,
		},
		{
			id:    fingerprint.SettingInitialWindowSize,
			value: source.initialWindowSize,
		},
	}

	return differSettings(diffs, wire.HTTP2, settings, source.connectionFlow)
}

// describeCiphers lists cipher suites in ascending order, or "none".
func describeCiphers(suites []uint16) string {
	if len(suites) == 0 {
		return "none"
	}

	sorted := slices.Sorted(slices.Values(suites))
	names := make([]string, len(sorted))

	for index, suite := range sorted {
		names[index] = fmt.Sprintf("0x%04x", suite)
	}

	return strings.Join(names, " ")
}

// describeCompression lists certificate compression algorithms in
// advertised order, or "none".
func describeCompression(algorithms []utls.CertCompressionAlgo) string {
	if len(algorithms) == 0 {
		return "none"
	}

	names := make([]string, len(algorithms))
	for index, algorithm := range algorithms {
		names[index] = compressionName(algorithm)
	}

	return strings.Join(names, " ")
}

// compressionName names a certificate compression algorithm.
func compressionName(algorithm utls.CertCompressionAlgo) string {
	switch algorithm {
	case utls.CertCompressionZlib:
		return "zlib"
	case utls.CertCompressionBrotli:
		return "brotli"
	case utls.CertCompressionZstd:
		return "zstd"
	default:
		return fmt.Sprintf("0x%04x", uint16(algorithm))
	}
}
