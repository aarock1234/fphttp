package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// difference is one wire field whose source value differs from the
// catalog's.
type difference struct {
	field   string
	catalog string
	source  string
}

// String describes the difference.
func (d difference) String() string {
	return fmt.Sprintf("%s: catalog %s, source %s", d.field, d.catalog, d.source)
}

// differ appends a difference for field when the catalog and source values
// differ.
func differ[T comparable](diffs []difference, field string, catalogValue, sourceValue T) []difference {
	if catalogValue == sourceValue {
		return diffs
	}

	return append(diffs, difference{
		field:   field,
		catalog: fmt.Sprint(catalogValue),
		source:  fmt.Sprint(sourceValue),
	})
}

// checkWires derives the wire of every platform among t's releases with
// derive, and compares each release's catalog wire with it using compare.
//
// A difference found for several browsers or platforms is reported once,
// naming all of them. A platform whose derivation fails is reported once and
// its releases are skipped.
func checkWires[F any](
	t target,
	derive func(catalog.Platform) (F, error),
	compare func(*catalog.Wire, F) []difference,
) []finding {
	derived, findings := derivePlatforms(t, derive)

	var mismatches mismatchSet

	for _, entry := range t.entries {
		features, ok := derived[entry.Platform]
		if !ok {
			continue
		}

		mismatches.add(entry, compare(entry.Wire, features))
	}

	return append(findings, mismatches.findings(t)...)
}

// derivePlatforms derives the wire of every platform among t's releases.
// A platform whose derivation fails is reported and left out of the result.
func derivePlatforms[F any](t target, derive func(catalog.Platform) (F, error)) (map[catalog.Platform]F, []finding) {
	var findings []finding

	derived := make(map[catalog.Platform]F)

	for _, platform := range t.platforms() {
		features, err := derive(platform)
		if err != nil {
			findings = append(findings, t.derivationFinding(fmt.Errorf("%s: %w", platform, err)))

			continue
		}

		derived[platform] = features
	}

	return derived, findings
}

// mismatchKey identifies one difference of one catalog wire.
type mismatchKey struct {
	wire       string
	difference difference
}

// mismatchScope lists the browsers and platforms that show one difference,
// in the order they were found.
type mismatchScope struct {
	browsers  []catalog.Browser
	platforms []catalog.Platform
}

// mismatchSet collects differences across a target's releases, so a
// difference several releases share is reported once. The zero value is
// empty and ready to use.
type mismatchSet struct {
	order  []mismatchKey
	scopes map[mismatchKey]*mismatchScope
}

// add records the differences found for entry's wire.
func (s *mismatchSet) add(entry catalog.Entry, diffs []difference) {
	for _, diff := range diffs {
		key := mismatchKey{
			wire:       entry.Wire.Name,
			difference: diff,
		}

		scope, seen := s.scopes[key]
		if !seen {
			if s.scopes == nil {
				s.scopes = make(map[mismatchKey]*mismatchScope)
			}

			scope = &mismatchScope{}
			s.scopes[key] = scope
			s.order = append(s.order, key)
		}

		scope.add(entry)
	}
}

// findings reports every collected difference of t, in the order found.
func (s *mismatchSet) findings(t target) []finding {
	findings := make([]finding, 0, len(s.order))

	for _, key := range s.order {
		findings = append(findings, t.mismatchFinding(key, s.scopes[key]))
	}

	return findings
}

// add records that entry's wire shows the difference.
func (s *mismatchScope) add(entry catalog.Entry) {
	if !slices.Contains(s.browsers, entry.Browser) {
		s.browsers = append(s.browsers, entry.Browser)
	}

	if !slices.Contains(s.platforms, entry.Platform) {
		s.platforms = append(s.platforms, entry.Platform)
	}
}

// mismatchFinding reports one difference with the releases that show it.
func (t target) mismatchFinding(key mismatchKey, scope *mismatchScope) finding {
	browsers := joinNames(scope.browsers)
	platforms := joinNames(scope.platforms)

	release := fmt.Sprintf("%s %d", browsers, t.key.major)
	if t.key.family == familyBrave {
		release = fmt.Sprintf("%s on chromium %d", browsers, t.key.major)
	}

	return finding{
		kind:    findingMismatch,
		subject: fmt.Sprintf("%s on %s (source %s, wire %s)", release, platforms, t.representative.Version, key.wire),
		detail:  key.difference.String(),
	}
}

// joinNames lists browser or platform names separated by commas.
func joinNames[T ~string](names []T) string {
	parts := make([]string, len(names))
	for index, name := range names {
		parts[index] = string(name)
	}

	return strings.Join(parts, ", ")
}
