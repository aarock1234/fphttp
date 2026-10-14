package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/releasefetch"
)

// Brave declares its network feature overrides in one of two brave-core
// files, relative to the repository root. Brave moved them from the
// OVERRIDE_FEATURE_DEFAULT_STATES list to the patch in 1.95, so a release
// names each feature in at most one of them.
const (
	// braveFeaturesPatch is Brave's patch to Chromium's
	// net/base/features.cc, which marks every feature default it replaces
	// with BASE_OVERRIDDEN_FEATURE.
	braveFeaturesPatch = "patches/net-base-features.cc.patch"

	// braveFeaturesSource is Brave's extension of Chromium's
	// net/base/features.cc, whose OVERRIDE_FEATURE_DEFAULT_STATES list
	// replaces feature defaults.
	braveFeaturesSource = "chromium_src/net/base/features.cc"
)

// defaultStatesMacro starts every feature default list in Brave's source.
const defaultStatesMacro = "OVERRIDE_FEATURE_DEFAULT_STATES"

var (
	// overriddenFeaturePattern matches a feature default Brave's patch
	// replaces, such as "BASE_OVERRIDDEN_FEATURE(kTLSTrustAnchorIDs,
	// base::FEATURE_DISABLED_BY_DEFAULT)".
	overriddenFeaturePattern = regexp.MustCompile(`BASE_OVERRIDDEN_FEATURE\(\s*k?(\w+)\s*,\s*base::FEATURE_(ENABLED|DISABLED)_BY_DEFAULT\s*\)`)

	// defaultStatesPattern matches one OVERRIDE_FEATURE_DEFAULT_STATES list
	// and captures its entries.
	defaultStatesPattern = regexp.MustCompile(`(?s)OVERRIDE_FEATURE_DEFAULT_STATES\(\{\{(.*?)\}\}\);`)

	// defaultStateEntryPattern matches one entry of such a list, such as
	// "{kTLSTrustAnchorIDs, base::FEATURE_DISABLED_BY_DEFAULT}".
	defaultStateEntryPattern = regexp.MustCompile(`\{\s*k?(\w+)\s*,\s*base::FEATURE_(ENABLED|DISABLED)_BY_DEFAULT\s*\}`)
)

// braveOverrides returns the feature defaults Brave replaces at tag, read
// from both its features patch and its OVERRIDE_FEATURE_DEFAULT_STATES
// list. A release without one of the files overrides nothing there.
func braveOverrides(ctx context.Context, sources *releasefetch.Fetcher, tag string) (featureOverrides, error) {
	patch, err := fetchBraveFile(ctx, sources, tag, braveFeaturesPatch)
	if err != nil {
		return nil, err
	}

	source, err := fetchBraveFile(ctx, sources, tag, braveFeaturesSource)
	if err != nil {
		return nil, err
	}

	listed, err := parseDefaultStateOverrides(source)
	if err != nil {
		return nil, fmt.Errorf("brave %s %s: %w", tag, braveFeaturesSource, err)
	}

	overrides := parsePatchOverrides(patch)
	maps.Copy(overrides, listed)

	return overrides, nil
}

// fetchBraveFile returns the text of path in brave-core at tag, or "" when
// the release has no such file.
func fetchBraveFile(ctx context.Context, sources *releasefetch.Fetcher, tag, path string) (string, error) {
	body, err := sources.Fetch(ctx, braveCoreURL+tag+"/"+path)
	if releasefetch.IsNotFound(err) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("brave %s: %w", tag, err)
	}

	return string(body), nil
}

// parsePatchOverrides reads the overridden feature defaults that a patch
// adds. Removed lines are Chromium's own declarations and are ignored.
func parsePatchOverrides(patch string) featureOverrides {
	var added strings.Builder

	for line := range strings.Lines(patch) {
		if strings.HasPrefix(line, "+++") {
			continue
		}

		if text, ok := strings.CutPrefix(line, "+"); ok {
			added.WriteString(text)
		}
	}

	overrides := make(featureOverrides)

	for _, match := range overriddenFeaturePattern.FindAllStringSubmatch(added.String(), -1) {
		overrides[match[1]] = match[2] == "ENABLED"
	}

	return overrides
}

// parseDefaultStateOverrides reads the entries of every
// OVERRIDE_FEATURE_DEFAULT_STATES list in source. A list the parser cannot
// read completely is an error, so a new form gets reviewed rather than
// silently dropped.
func parseDefaultStateOverrides(source string) (featureOverrides, error) {
	lists := defaultStatesPattern.FindAllStringSubmatch(source, -1)
	if len(lists) != strings.Count(source, defaultStatesMacro) {
		return nil, errors.New("unrecognized " + defaultStatesMacro + " list")
	}

	overrides := make(featureOverrides)

	for _, list := range lists {
		if err := addDefaultStates(overrides, list[1]); err != nil {
			return nil, err
		}
	}

	return overrides, nil
}

// addDefaultStates adds the entries of one OVERRIDE_FEATURE_DEFAULT_STATES
// list to overrides. The list must apply on every platform and contain only
// entries the pattern reads.
func addDefaultStates(overrides featureOverrides, entries string) error {
	for line := range strings.Lines(entries) {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			return fmt.Errorf("preprocessor directive in %s list: %q", defaultStatesMacro, strings.TrimSpace(line))
		}
	}

	matches := defaultStateEntryPattern.FindAllStringSubmatch(entries, -1)
	if len(matches) != strings.Count(entries, "base::FEATURE_") {
		return fmt.Errorf("unrecognized entry in %s list", defaultStatesMacro)
	}

	for _, match := range matches {
		overrides[match[1]] = match[2] == "ENABLED"
	}

	return nil
}
