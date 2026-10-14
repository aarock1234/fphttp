package main

import (
	"context"
	"fmt"
	"strings"
)

// braveCoreURL is the raw file prefix of the brave-core repository.
const braveCoreURL = "https://raw.githubusercontent.com/brave/brave-core/"

// bravePackage is the part of brave-core's package.json that pins the
// Chromium build a Brave release is made from.
type bravePackage struct {
	Config braveConfig `json:"config"`
}

// braveConfig is the config object of brave-core's package.json.
type braveConfig struct {
	Projects braveProjects `json:"projects"`
}

// braveProjects lists the upstream projects brave-core builds on.
type braveProjects struct {
	Chrome braveProject `json:"chrome"`
}

// braveProject is one pinned upstream project.
type braveProject struct {
	Tag string `json:"tag"`
}

// verifyBrave derives the wire of a target's Brave release from the
// Chromium build brave-core pins, with Brave's feature overrides, and
// compares it with every Brave release on that Chromium major.
func verifyBrave(ctx context.Context, sources *fetcher, t target) []finding {
	tag := "v" + t.representative.Version

	chromiumTag, err := braveChromiumPin(ctx, sources, tag)
	if err != nil {
		return []finding{t.derivationFinding(err)}
	}

	overrides, err := braveOverrides(ctx, sources, tag)
	if err != nil {
		return []finding{t.derivationFinding(err)}
	}

	source, err := fetchChromiumSource(ctx, sources, chromiumTag)
	if err != nil {
		return []finding{t.derivationFinding(err)}
	}

	var findings []finding

	// The catalog chooses a Brave release's span by the Chromium build its
	// release notes name; the pin is authoritative.
	if pinned := versionMajor(chromiumTag); pinned != t.key.major {
		findings = append(findings, finding{
			kind:    findingMismatch,
			subject: fmt.Sprintf("brave %s", t.representative.Version),
			detail:  fmt.Sprintf("chromium major: catalog %d (engine %s), source pin %s", t.key.major, t.representative.Engine, chromiumTag),
		})
	}

	return append(findings, checkChromiumWires(ctx, sources, t, source, overrides)...)
}

// braveChromiumPin returns the Chromium build brave-core pins at tag.
func braveChromiumPin(ctx context.Context, sources *fetcher, tag string) (string, error) {
	pin, err := sources.fetchJSON[bravePackage](ctx, braveCoreURL+tag+"/package.json")
	if err != nil {
		return "", fmt.Errorf("brave %s: %w", tag, err)
	}

	chromiumTag := pin.Config.Projects.Chrome.Tag
	if strings.Count(chromiumTag, ".") != 3 || versionMajor(chromiumTag) == 0 {
		return "", fmt.Errorf("brave %s: package.json pins no full Chromium build: %q", tag, chromiumTag)
	}

	return chromiumTag, nil
}
