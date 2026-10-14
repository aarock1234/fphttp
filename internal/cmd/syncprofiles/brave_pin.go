package main

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/aarock1234/fphttp/v2/internal/releasefetch"
)

// bravePackage is the part of brave-core's package.json that pins the
// Chromium build.
type bravePackage struct {
	Config struct {
		Projects struct {
			Chrome struct {
				Tag string `json:"tag"`
			} `json:"chrome"`
		} `json:"projects"`
	} `json:"config"`
}

// pinBraveEngines sets each build's engine to the Chromium build that
// brave-core pins for it. Without a usable pin a build keeps the Chromium
// build its changelog names; without either it is dropped with a warning.
func (c *collector) pinBraveEngines(ctx context.Context, builds []release) ([]release, error) {
	versions := make([]string, 0, len(builds))
	for _, build := range builds {
		versions = append(versions, build.version)
	}

	slices.Sort(versions)
	versions = slices.Compact(versions)

	pinList, err := mapConcurrently(ctx, versions, c.braveChromiumPin)
	if err != nil {
		return nil, err
	}

	pins := make(map[string]string, len(versions))
	for index, version := range versions {
		pins[version] = pinList[index]
	}

	pinned := make([]release, 0, len(builds))
	for _, build := range builds {
		if pin := pins[build.version]; pin != "" {
			build.engine = pin
		}

		if build.engine == "" {
			slog.Warn("skipping Brave build without a known Chromium build",
				slog.String("version", build.version),
				slog.String("platform", build.platform.String()),
			)

			continue
		}

		pinned = append(pinned, build)
	}

	return pinned, nil
}

// braveChromiumPin returns the exact Chromium build that brave-core pins for
// a Brave version. It returns "" with a warning when brave-core has no tag
// for the version or the tag pins no exact build. Any other failure is
// returned, so a transient outage fails the run instead of dropping builds.
func (c *collector) braveChromiumPin(ctx context.Context, version string) (string, error) {
	packageURL := "https://raw.githubusercontent.com/brave/brave-core/v" + version + "/package.json"

	project, err := c.fetcher.FetchJSON[bravePackage](ctx, packageURL)
	if releasefetch.IsNotFound(err) {
		slog.Warn("no brave-core tag for Brave version",
			slog.String("version", version),
		)

		return "", nil
	}

	if err != nil {
		return "", err
	}

	pin := project.Config.Projects.Chrome.Tag
	if !numericVersion(pin) || strings.Count(pin, ".") != 3 {
		slog.Warn("ignoring Brave Chromium pin that is not an exact build",
			slog.String("version", version),
			slog.String("pin", pin),
		)

		return "", nil
	}

	return pin, nil
}
