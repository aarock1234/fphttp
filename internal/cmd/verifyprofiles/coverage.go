package main

import (
	"errors"
	"fmt"

	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// checkCoverage reports every generated Chromium and Firefox build that is
// newer than the newest release the hand-written spans support. Lookup
// resolves such a build to an older release with ErrVersionTooNew, so the
// catalog would silently stop short of it.
//
// Builds older than every span, such as Firefox for Android before 126, and
// builds a coverage decision drops, such as Edge before 119, are deliberate
// gaps and not reported. Safari releases are covered only by captures and
// are not checked.
func checkCoverage() []finding {
	var findings []finding

	for build := range catalog.Builds() {
		if build.Browser == catalog.Safari {
			continue
		}

		newest, err := catalog.Lookup(build.Browser, build.Platform, build.Version)
		if !errors.Is(err, catalog.ErrVersionTooNew) {
			continue
		}

		findings = append(findings, finding{
			kind:    findingNoSpan,
			subject: buildSubject(build),
			detail:  fmt.Sprintf("newer than every span; the newest supported release is %s", newest.Version),
		})
	}

	return findings
}

// buildSubject names a generated build, with its engine build when the
// feeds state one that differs from the product version.
func buildSubject(build catalog.Build) string {
	subject := fmt.Sprintf("%s %s on %s", build.Browser, build.Version, build.Platform)
	if build.Engine != "" && build.Engine != build.Version {
		subject += " (engine " + build.Engine + ")"
	}

	return subject
}
