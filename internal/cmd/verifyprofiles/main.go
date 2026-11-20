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
// Every file is read at a release tag or commit, so its content never
// changes. Each one is cached on disk as <cache>/<sha256(url)>.data and
// reused by every later run without revalidation:
//
//	go run ./internal/cmd/verifyprofiles
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
	cacheDir string
	timeout  time.Duration
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

	sources := newFetcher(opts.cacheDir)

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

	flag.StringVar(&opts.cacheDir, "cache", defaultCacheDir(), "cache directory for source files, which never expire; empty disables caching")
	flag.DurationVar(&opts.timeout, "timeout", defaultTimeout, "deadline for the complete run, including every fetch")
	flag.Parse()

	if flag.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected arguments: %q", flag.Args())
	}

	if opts.timeout <= 0 {
		return options{}, errors.New("-timeout must be positive")
	}

	return opts, nil
}

// defaultCacheDir returns the per-user cache directory for source files, or
// "" when the platform defines none.
func defaultCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}

	return filepath.Join(dir, "fphttp", "verifyprofiles")
}
