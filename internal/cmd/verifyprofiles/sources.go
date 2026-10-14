package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/releasefetch"
)

// deriveConcurrency bounds the targets derived at once. The fetcher
// separately bounds network requests.
const deriveConcurrency = 8

// checkSources derives the wire of every Chromium, Brave, and Firefox major
// in the catalog from source and compares it with the catalog's wires.
//
// A target that cannot be derived is a finding, not a failure; only the end
// of ctx stops the check and returns an error.
func checkSources(ctx context.Context, sources *releasefetch.Fetcher) ([]finding, error) {
	targets := collectTargets()

	slog.InfoContext(ctx, "deriving wires from browser source", slog.Int("targets", len(targets)))

	results := mapBounded(ctx, targets, deriveConcurrency, func(ctx context.Context, t target) []finding {
		return verifyTarget(ctx, sources, t)
	})

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("derive wires from source: %w", err)
	}

	return slices.Concat(results...), nil
}

// verifyTarget derives one target's wire and compares it with the catalog.
func verifyTarget(ctx context.Context, sources *releasefetch.Fetcher, t target) []finding {
	if t.representative.Version == "" {
		return []finding{t.derivationFinding(errors.New("no release of the source browser to derive this major from"))}
	}

	switch t.key.family {
	case familyChromium:
		return verifyChromium(ctx, sources, t)
	case familyBrave:
		return verifyBrave(ctx, sources, t)
	case familyFirefox, familyFirefoxESR:
		return verifyFirefox(ctx, sources, t)
	default:
		return []finding{t.derivationFinding(fmt.Errorf("unknown source family %q", t.key.family))}
	}
}
