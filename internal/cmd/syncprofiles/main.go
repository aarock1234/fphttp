// Command syncprofiles regenerates internal/catalog/builds_gen.go from official
// browser release feeds. The generated table lists the newest published build
// of every browser major version on every platform.
//
// The command imports neither the root package nor internal/catalog, so it
// still builds when the generated file is broken. It runs through go generate
// in internal/catalog:
//
//	go generate ./internal/catalog
//
// Every successful response is cached on disk under the -through date and
// reused by later runs for the same date. A successful run removes the
// responses cached for other dates.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// runTimeout bounds one complete run, including every fetch on a cold cache.
const runTimeout = 15 * time.Minute

// options holds the command-line flags.
type options struct {
	out      string
	since    string
	through  string
	cacheDir string
}

func main() {
	if err := run(); err != nil {
		slog.Error("syncprofiles failed", slog.Any("error", err))
		os.Exit(1)
	}
}

// run collects every release feed, keeps the newest build of each major
// version, and writes the generated catalog table.
func run() error {
	opts, err := parseOptions()
	if err != nil {
		return err
	}

	window, err := parseWindow(opts.since, opts.through)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	collector := &collector{
		fetcher: newFetcher(responseCacheDir(opts)),
		window:  window,
	}

	releases, err := collector.collectAll(ctx)
	if err != nil {
		return err
	}

	builds := newestBuilds(releases)

	source, err := renderBuilds(builds)
	if err != nil {
		return err
	}

	if err := replaceFile(opts.out, source); err != nil {
		return err
	}

	slog.Info("wrote browser builds",
		slog.Int("count", len(builds)),
		slog.String("path", opts.out),
	)

	if err := pruneResponseCache(opts.cacheDir, opts.through); err != nil {
		slog.Warn("pruning response cache failed", slog.Any("error", err))
	}

	return nil
}

// parseOptions reads the command-line flags.
func parseOptions() (options, error) {
	var opts options

	flag.StringVar(&opts.out, "out", "builds_gen.go", "generated Go file to write")
	flag.StringVar(&opts.since, "since", "2023-01-01", "first included release date (YYYY-MM-DD, UTC)")
	flag.StringVar(&opts.through, "through", time.Now().UTC().Format(time.DateOnly), "last included release date (YYYY-MM-DD, UTC)")
	flag.StringVar(&opts.cacheDir, "cache", defaultCacheDir(), "response cache directory with one subdirectory per -through date; a successful run removes the other dates; empty disables caching")
	flag.Parse()

	if flag.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %q", flag.Args())
	}

	if opts.out == "" {
		return options{}, errors.New("-out must not be empty")
	}

	return opts, nil
}
