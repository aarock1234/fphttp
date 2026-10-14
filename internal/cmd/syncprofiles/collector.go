package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
)

// collector gathers published browser releases from official release feeds.
// Every collector method returns only releases published inside window.
type collector struct {
	fetcher *fetcher
	window  window
}

// feed is one release feed and the method that collects it.
type feed struct {
	name    string
	collect func(context.Context) ([]release, error)
}

// collectAll collects every release feed concurrently and returns their
// combined releases. The first failing feed fails the whole collection.
func (c *collector) collectAll(ctx context.Context) ([]release, error) {
	feeds := []feed{
		{
			name:    "Chrome",
			collect: c.chrome,
		},
		{
			name:    "Edge desktop",
			collect: c.edgeDesktop,
		},
		{
			name:    "Edge Android",
			collect: c.edgeAndroid,
		},
		{
			name:    "Brave",
			collect: c.brave,
		},
		{
			name:    "Firefox desktop",
			collect: c.firefoxDesktop,
		},
		{
			name:    "Firefox Android",
			collect: c.firefoxAndroid,
		},
		{
			name:    "Safari",
			collect: c.safari,
		},
	}

	perFeed, err := mapConcurrently(ctx, feeds, collectFeed)
	if err != nil {
		return nil, err
	}

	return slices.Concat(perFeed...), nil
}

// collectFeed collects one feed and reports how many releases it found.
func collectFeed(ctx context.Context, source feed) ([]release, error) {
	releases, err := source.collect(ctx)
	if err != nil {
		return nil, fmt.Errorf("collect %s releases: %w", source.name, err)
	}

	slog.Info("collected releases",
		slog.String("feed", source.name),
		slog.Int("count", len(releases)),
	)

	return releases, nil
}
