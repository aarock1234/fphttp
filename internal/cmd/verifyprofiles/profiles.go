package main

import (
	"fmt"

	fphttp "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/internal/catalog"
)

// checkProfiles asks NewProfile for every cataloged release by its own
// version. Each must succeed, resolve to that same build, and carry a
// User-Agent.
func checkProfiles() []finding {
	var findings []finding

	for entry := range catalog.Entries() {
		if problem, failed := checkProfile(entry); failed {
			findings = append(findings, problem)
		}
	}

	return findings
}

// checkProfile reports the problem with the profile of one release, if any.
func checkProfile(entry catalog.Entry) (finding, bool) {
	subject := fmt.Sprintf("%s %s on %s", entry.Browser, entry.Version, entry.Platform)

	profile, err := fphttp.NewProfile(
		fphttp.Browser(entry.Browser),
		fphttp.Platform(entry.Platform),
		fphttp.Version(entry.Version),
	)
	if err != nil {
		return profileFinding(subject, fmt.Sprintf("NewProfile failed: %v", err)), true
	}

	if resolved := string(profile.Version()); resolved != entry.Version {
		return profileFinding(subject, fmt.Sprintf("NewProfile resolved %s", resolved)), true
	}

	if profile.Header.Get("User-Agent") == "" {
		return profileFinding(subject, "profile has no User-Agent"), true
	}

	return finding{}, false
}

// profileFinding builds a PROFILE ERROR finding.
func profileFinding(subject, detail string) finding {
	return finding{
		kind:    findingProfile,
		subject: subject,
		detail:  detail,
	}
}
