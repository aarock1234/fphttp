// Command syncprofiles imports published releases from browser-owned sources.
// It records missing fingerprint evidence instead of manufacturing wire aliases.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"time"

	"github.com/aarock1234/fphttp/v2/browser"
)

type importer struct {
	client   *http.Client
	since    time.Time
	through  time.Time
	cacheDir string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	output := flag.String("out", "browser/data/releases.json", "release inventory output")
	since := flag.String("since", "2023-01-01", "first included release date")
	through := flag.String("through", "2026-10-13", "last included release date")
	bootstrap := flag.Bool("bootstrap", false, "import the requested Chrome release families first (partial inventory)")
	cacheDir := flag.String("cache", filepath.Join(os.TempDir(), "fphttp-primary-release-cache"), "cache successful public-source responses outside the repository")
	flag.Parse()

	first, err := time.Parse(time.DateOnly, *since)
	if err != nil {
		return fmt.Errorf("parse since: %w", err)
	}
	last, err := time.Parse(time.DateOnly, *through)
	if err != nil {
		return fmt.Errorf("parse through: %w", err)
	}
	if first.After(last) {
		return errors.New("since must not be after through")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
	defer cancel()

	importer := &importer{
		client:   &http.Client{Timeout: 30 * time.Second},
		since:    first,
		through:  last.AddDate(0, 0, 1),
		cacheDir: filepath.Join(*cacheDir, *through),
	}

	var entries []browser.Descriptor
	if *bootstrap {
		entries, err = importer.bootstrapChrome(ctx)
	} else {
		entries, err = importer.collect(ctx)
	}
	if err != nil {
		return err
	}
	entries = uniqueEntries(entries)
	slices.SortFunc(entries, func(a, b browser.Descriptor) int {
		return stringsCompare(a.ID, b.ID)
	})
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encode release inventory: %w", err)
	}
	data = append(data, '\n')
	fmt.Println("Deriving Chromium representative configurations from tagged primary source...")
	definitions, err := importer.chromiumSources(ctx, entries)
	if err != nil {
		return err
	}
	definitionData, err := json.MarshalIndent(definitions, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Chromium definitions: %w", err)
	}
	firefoxDefinitions := importer.firefoxSources(ctx, entries)
	firefoxData, err := json.MarshalIndent(firefoxDefinitions, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Firefox definitions: %w", err)
	}
	if firefoxDefinitions == nil {
		firefoxData = []byte("[]")
	}
	braveDefinitions := importer.braveSources(ctx, entries)
	braveData, err := json.MarshalIndent(braveDefinitions, "", "  ")
	if err != nil {
		return fmt.Errorf("encode Brave definitions: %w", err)
	}
	if braveDefinitions == nil {
		braveData = []byte("[]")
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		return fmt.Errorf("write inventory: %w", err)
	}
	definitionPath := filepath.Join(filepath.Dir(*output), "chromium.json")
	if err := os.WriteFile(definitionPath, append(definitionData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write Chromium definitions: %w", err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(*output), "firefox.json"), append(firefoxData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write Firefox definitions: %w", err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(*output), "brave.json"), append(braveData, '\n'), 0o644); err != nil {
		return fmt.Errorf("write Brave definitions: %w", err)
	}

	fmt.Printf("Imported %d release/platform entries into %s\n", len(entries), *output)

	return nil
}

func (i *importer) collect(ctx context.Context) ([]browser.Descriptor, error) {
	collectors := []struct {
		name string
		load func(context.Context) ([]browser.Descriptor, error)
	}{
		{
			name: "Chrome",
			load: i.chrome,
		},
		{
			name: "Firefox",
			load: i.firefox,
		},
		{
			name: "Brave",
			load: i.brave,
		},
		{
			name: "Edge",
			load: i.edge,
		},
		{
			name: "Safari",
			load: i.safari,
		},
		{
			name: "Firefox iOS",
			load: i.firefoxIOS,
		},
	}

	var entries []browser.Descriptor
	for _, collector := range collectors {
		fmt.Printf("Importing %s primary release metadata...\n", collector.name)
		result, err := collector.load(ctx)
		if err != nil {
			return nil, fmt.Errorf("import %s: %w", collector.name, err)
		}
		entries = append(entries, result...)
	}

	return entries, nil
}

func stringsCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}

	return 0
}
