package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// defaultCacheDir returns the per-user cache directory for fetched responses,
// or "" when the platform defines none.
func defaultCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}

	return filepath.Join(dir, "fphttp", "syncprofiles")
}

// responseCacheDir returns the cache directory for this run's -through date,
// or "" when caching is disabled.
func responseCacheDir(opts options) string {
	if opts.cacheDir == "" {
		return ""
	}

	return filepath.Join(opts.cacheDir, opts.through)
}

// pruneResponseCache removes the responses cached for every -through date
// other than keep, so the cache holds one date at a time. It removes only
// subdirectories of root named for a date and leaves every other entry in
// place.
func pruneResponseCache(root, keep string) error {
	if root == "" {
		return nil
	}

	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("read response cache: %w", err)
	}

	var failures []error
	for _, entry := range entries {
		if !staleCacheDate(entry, keep) {
			continue
		}

		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			failures = append(failures, fmt.Errorf("remove responses cached for %s: %w", entry.Name(), err))
		}
	}

	return errors.Join(failures...)
}

// staleCacheDate reports whether entry is the cache directory of a -through
// date other than keep.
func staleCacheDate(entry os.DirEntry, keep string) bool {
	if !entry.IsDir() || entry.Name() == keep {
		return false
	}

	_, err := time.Parse(time.DateOnly, entry.Name())

	return err == nil
}
