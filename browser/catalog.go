package browser

import (
	"cmp"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ErrUnsupported identifies an unknown product, build, platform, or variant.
var ErrUnsupported = errors.New("browser: unsupported selection")

// ErrUnavailable identifies a known release whose wire definition is incomplete.
var ErrUnavailable = errors.New("browser: fingerprint unavailable")

//go:embed data/releases.json
var releaseData []byte

var catalogEntries = loadCatalog()

func loadCatalog() []Descriptor {
	var entries []Descriptor
	if err := json.Unmarshal(releaseData, &entries); err != nil {
		panic(fmt.Sprintf("browser: invalid embedded release inventory: %v", err))
	}

	entries = appendProfileDefinitions(entries)
	slices.SortFunc(entries, compareDescriptors)

	return entries
}

// Catalog returns independently owned release and variant descriptors.
// Unavailable entries remain visible and are rejected by Resolve.
func Catalog() []Descriptor {
	entries := make([]Descriptor, len(catalogEntries))
	for i, entry := range catalogEntries {
		entries[i] = cloneDescriptor(entry)
	}

	return entries
}

// Resolve selects the newest matching published release before checking its
// availability. It never silently downgrades to an older available release.
func Resolve(selector Selector) (*Profile, error) {
	selected, err := selectedDescriptor(selector)
	if err != nil {
		return nil, err
	}
	if !selected.Available {
		return nil, fmt.Errorf("%w: %s", ErrUnavailable, selected.ID)
	}

	fingerprint, err := fingerprintFor(selected)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", selected.ID, err)
	}
	if err := fingerprint.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", selected.ID, err)
	}

	return &Profile{
		descriptor:  selected,
		fingerprint: fingerprint,
	}, nil
}

// ResolveIdentity selects immutable published identity metadata without a wire
// profile. Fingerprint returns nil; clients must supply an explicit fingerprint.
// Catalog coverage remains descriptive and does not validate that override.
func ResolveIdentity(selector Selector) (*Profile, error) {
	descriptor, err := selectedDescriptor(selector)
	if err != nil {
		return nil, err
	}

	return &Profile{descriptor: descriptor}, nil
}

func selectedDescriptor(selector Selector) (Descriptor, error) {
	if err := validateVersionSelector(selector.Version); err != nil {
		return Descriptor{}, err
	}

	var selected *Descriptor
	for index := range catalogEntries {
		entry := &catalogEntries[index]
		if !matchesSelector(*entry, selector) {
			continue
		}
		if selected == nil || compareVersions(entry.Version, selected.Version) > 0 {
			selected = entry
		}
	}
	if selected == nil {
		return Descriptor{}, fmt.Errorf("%w: %s %q on %s", ErrUnsupported, selector.Browser, selector.Version, selector.Platform)
	}

	return cloneDescriptor(*selected), nil
}

func matchesSelector(entry Descriptor, selector Selector) bool {
	if entry.Browser != selector.Browser || entry.Platform != selector.Platform {
		return false
	}
	if selector.Version != "" && entry.Version != selector.Version &&
		!strings.HasPrefix(entry.Version, selector.Version+".") {
		return false
	}
	if selector.OSBuild != "" && entry.OSBuild != selector.OSBuild {
		return false
	}
	if selector.Device != "" && entry.Device != selector.Device {
		return false
	}
	if selector.Channel != "" && entry.Channel != selector.Channel {
		return false
	}
	if selector.Variant != "" {
		return entry.Variant == selector.Variant
	}

	return entry.Variant == "source-default"
}

func validateVersionSelector(version string) error {
	if version == "" {
		return nil
	}

	for _, part := range strings.Split(version, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return fmt.Errorf("%w: invalid numeric version %q", ErrUnsupported, version)
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return fmt.Errorf("%w: invalid numeric version %q", ErrUnsupported, version)
		}
	}

	return nil
}

func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := range max(len(aParts), len(bParts)) {
		var aPart, bPart uint64
		if i < len(aParts) {
			aPart, _ = strconv.ParseUint(aParts[i], 10, 32)
		}
		if i < len(bParts) {
			bPart, _ = strconv.ParseUint(bParts[i], 10, 32)
		}
		if order := cmp.Compare(aPart, bPart); order != 0 {
			return order
		}
	}

	return 0
}

func compareDescriptors(a, b Descriptor) int {
	if order := cmp.Compare(a.Browser, b.Browser); order != 0 {
		return order
	}
	if order := cmp.Compare(a.Platform, b.Platform); order != 0 {
		return order
	}
	if order := compareVersions(a.Version, b.Version); order != 0 {
		return order
	}

	return cmp.Compare(a.ID, b.ID)
}
