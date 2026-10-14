package main

import (
	"context"
	"fmt"
	"slices"
	"strings"

	http "github.com/aarock1234/fphttp"
	"github.com/aarock1234/fphttp/browser"
)

type braveDefinition struct {
	Version       string             `json:"version"`
	EngineVersion string             `json:"engine_version"`
	Platform      http.Platform      `json:"platform"`
	Chromium      chromiumDefinition `json:"chromium"`
	Sources       []browser.Source   `json:"sources"`
}

type bravePackage struct {
	Config struct {
		Projects struct {
			Chrome struct {
				Tag string `json:"tag"`
			} `json:"chrome"`
		} `json:"projects"`
	} `json:"config"`
}

func (i *importer) braveSources(ctx context.Context, entries []browser.Descriptor) []braveDefinition {
	selected := make(map[string]browser.Descriptor)
	for _, entry := range entries {
		if entry.Browser != http.BrowserBrave || entry.Platform == http.PlatformIOS || entry.Platform == http.PlatformIPadOS {
			continue
		}
		parts := strings.Split(entry.Version, ".")
		if len(parts) != 3 {
			continue
		}
		key := string(entry.Platform) + "/" + strings.Join(parts[:2], ".")
		previous, found := selected[key]
		if !found || newerVersion(entry.Version, previous.Version) {
			selected[key] = entry
		}
	}
	packages := make(map[string]bravePackage)
	engines := make(map[string]map[string]string)
	var definitions []braveDefinition
	for _, entry := range selected {
		tag := "v" + entry.Version
		packageURL := "https://raw.githubusercontent.com/brave/brave-core/" + tag + "/package.json"
		project, found := packages[tag]
		if !found {
			var err error
			project, err = fetchJSON[bravePackage](ctx, i, packageURL)
			if err != nil {
				fmt.Printf("  unavailable Brave %s: %v\n", entry.Version, err)
				continue
			}
			packages[tag] = project
		}
		engine := project.Config.Projects.Chrome.Tag
		if !numericVersion(engine) || len(strings.Split(engine, ".")) != 4 {
			fmt.Printf("  unavailable Brave %s: missing exact Chromium pin\n", entry.Version)
			continue
		}
		files, found := engines[engine]
		if !found {
			var err error
			files, err = i.chromiumSourceFiles(ctx, engine)
			if err != nil {
				fmt.Printf("  unavailable Brave engine %s: %v\n", engine, err)
				continue
			}
			engines[engine] = files
		}
		base := entry
		base.Version = engine
		definition, err := deriveChromium(base, files)
		if err != nil {
			fmt.Printf("  unavailable Brave engine %s: %v\n", engine, err)
			continue
		}
		sources := []browser.Source{{
			URL:      packageURL,
			Revision: tag,
			Note:     "Exact Brave-owned Chromium build pin; complete downstream configuration and runtime differences remain partially covered.",
		}}
		patchURL := "https://raw.githubusercontent.com/brave/brave-core/" + tag + "/patches/net-base-features.cc.patch"
		patch, err := i.fetch(ctx, patchURL)
		if err == nil {
			compact := strings.NewReplacer(" ", "", "\t", "", "\n", "").Replace(string(patch))
			if strings.Contains(compact, "+BASE_OVERRIDDEN_FEATURE(kTLSTrustAnchorIDs,base::FEATURE_DISABLED_BY_DEFAULT)") {
				definition.TrustAnchorIDs = nil
			}
			sources = append(sources, browser.Source{
				URL:      patchURL,
				Revision: tag,
				Note:     "Brave's source-level feature overrides; other patches and product settings are not assumed identical to Chrome.",
			})
		} else {
			sources = append(sources, browser.Source{
				URL:      packageURL,
				Revision: tag,
				Note:     "The network-feature patch could not be obtained; only the exact engine pin is established for this partial definition.",
			})
		}
		definitions = append(definitions, braveDefinition{
			Version:       entry.Version,
			EngineVersion: engine,
			Platform:      entry.Platform,
			Chromium:      definition,
			Sources:       sources,
		})
	}
	slices.SortFunc(definitions, func(a, b braveDefinition) int {
		return strings.Compare(string(a.Platform)+"/"+a.Version, string(b.Platform)+"/"+b.Version)
	})

	return definitions
}
