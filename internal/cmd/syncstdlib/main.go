// Command syncstdlib merges production HTTP sources from a pinned Go revision.
// It stages every merge before changing the checkout and stops on conflicts.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
)

const modulePath = "github.com/aarock1234/fphttp"

type options struct {
	revision   string
	upstream   string
	outputFile string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var opts options
	flag.StringVar(&opts.revision, "ref", "master", "Go branch, tag, or commit to sync")
	flag.StringVar(&opts.upstream, "upstream", "", "existing bare Go checkout; otherwise create a temporary checkout")
	flag.StringVar(&opts.outputFile, "github-output", "", "append revision and changed outputs to this file")
	flag.Parse()
	if !validRevision(opts.revision) {
		return errors.New("invalid Go revision")
	}

	root, err := os.Getwd()
	if err != nil {
		return err
	}
	marker, err := os.ReadFile(filepath.Join(root, ".stdlib-version"))
	if err != nil {
		return fmt.Errorf("read upstream revision: %w", err)
	}
	base := strings.TrimSpace(string(marker))
	if !validRevision(base) {
		return errors.New(".stdlib-version does not contain a valid Go revision")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	work, err := os.MkdirTemp("", "fphttp-sync-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(work); err != nil {
			fmt.Fprintf(os.Stderr, "remove sync temporary directory: %v\n", err)
		}
	}()

	repo, err := openUpstream(ctx, opts.upstream, work)
	if err != nil {
		return err
	}
	revision, err := repo.resolve(ctx, opts.revision)
	if err != nil {
		return err
	}
	if revision == base {
		fmt.Printf("Already synced to Go %s\n", revision)

		return writeOutputs(opts.outputFile, revision, false)
	}
	if _, err := repo.resolve(ctx, base); err != nil {
		return fmt.Errorf("fetch base revision: %w", err)
	}

	syncer := &synchronizer{
		repo:     repo,
		root:     root,
		work:     work,
		base:     base,
		revision: revision,
	}
	changes, err := syncer.stageChanges(ctx)
	if err != nil {
		return err
	}
	if err := applyChanges(root, changes); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, ".stdlib-version"), []byte(revision+"\n"), 0o644); err != nil {
		return err
	}

	fmt.Printf("Synced %d production files to Go %s; build and review the diff before publishing.\n", len(changes), revision)

	return writeOutputs(opts.outputFile, revision, true)
}

func writeOutputs(path, revision string, changed bool) (err error) {
	if path == "" {
		return nil
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, file.Close())
	}()

	_, err = fmt.Fprintf(file, "revision=%s\nchanged=%t\n", revision, changed)

	return err
}
