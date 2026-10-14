// Command verifyprofiles checks the browser catalog in internal/catalog
// against the browsers' own source. It prints one line per finding and
// exits non-zero when there is any:
//
//   - PROFILE ERROR: NewProfile fails for a cataloged release, resolves it
//     to another build, or returns a profile without a User-Agent.
//   - NO SPAN: a generated Chromium or Firefox build is newer than every
//     hand-written span, so the catalog stops at an older release.
//   - MISMATCH: a wire feature derived from the source of a major's newest
//     build differs from the hand-written wire that covers the major.
//   - DERIVATION ERROR: the source could not be fetched, or it no longer has
//     a form the derivation recognizes, so the derivation needs review.
//
// The derivation reads compiled defaults: Chromium's network feature states
// and HTTP/2 constants at each Chrome tag, Brave's Chromium pin and feature
// overrides, and Firefox's preference defaults with GeckoView's Android
// overrides. Field trials, enterprise policy, and remote configuration are
// outside its scope. Safari publishes no network source, so its captured
// wires are not derived. Edge is checked through the Chromium major it
// shares with Chrome.
//
// Every fetched file is cached on disk as <cache>/<date>/<sha256(url)>.data,
// the layout syncprofiles uses, and reused by later runs with the same
// -cache-date:
//
//	go run ./internal/cmd/verifyprofiles -cache-date 2026-10-13
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

// defaultTimeout bounds one complete run, including every fetch on a cold
// cache.
const defaultTimeout = 20 * time.Minute

// options holds the command-line flags.
type options struct {
	cacheRoot string
	cacheDate string
	timeout   time.Duration
}

func main() {
	if err := run(); err != nil {
		slog.Error("verifyprofiles failed", slog.Any("error", err))
		os.Exit(1)
	}
}

// run checks every cataloged release, then derives each major's wire from
// browser source and compares it with the catalog. It prints every finding
// and fails when there is at least one.
func run() error {
	opts, err := parseOptions()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()

	sources := newFetcher(opts.responseCacheDir())

	findings := checkProfiles()
	findings = append(findings, checkCoverage()...)

	derived, err := checkSources(ctx, sources)
	if err != nil {
		return err
	}

	findings = append(findings, derived...)

	if err := printFindings(os.Stdout, findings); err != nil {
		return err
	}

	if len(findings) > 0 {
		return fmt.Errorf("catalog verification failed with findings: %d", len(findings))
	}

	slog.Info("catalog matches browser source")

	return nil
}

// parseOptions reads and validates the command-line flags.
func parseOptions() (options, error) {
	var opts options

	flag.StringVar(&opts.cacheRoot, "cache", defaultCacheRoot(), "response cache directory with one subdirectory per date, shared with syncprofiles; empty disables caching")
	flag.StringVar(&opts.cacheDate, "cache-date", time.Now().UTC().Format(time.DateOnly), "cache subdirectory to read and fill (YYYY-MM-DD); the -through date of a syncprofiles run reuses its cache")
	flag.DurationVar(&opts.timeout, "timeout", defaultTimeout, "deadline for the complete run, including every fetch")
	flag.Parse()

	if flag.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %q", flag.Args())
	}

	if _, err := time.Parse(time.DateOnly, opts.cacheDate); err != nil {
		return options{}, fmt.Errorf("parse -cache-date: %w", err)
	}

	if opts.timeout <= 0 {
		return options{}, errors.New("-timeout must be positive")
	}

	return opts, nil
}

// defaultCacheRoot returns the per-user cache directory syncprofiles uses,
// or "" when the platform defines none.
func defaultCacheRoot() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}

	return filepath.Join(dir, "fphttp", "syncprofiles")
}

// responseCacheDir returns the cache directory for -cache-date, or "" when
// caching is disabled.
func (o options) responseCacheDir() string {
	if o.cacheRoot == "" {
		return ""
	}

	return filepath.Join(o.cacheRoot, o.cacheDate)
}
