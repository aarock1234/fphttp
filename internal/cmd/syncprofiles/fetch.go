package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	httpfp "github.com/aarock1234/fphttp/v2"
	"github.com/aarock1234/fphttp/v2/browser"
)

const responseLimit = 32 << 20

func (i *importer) fetch(ctx context.Context, url string) ([]byte, error) {
	cachePath := filepath.Join(i.cacheDir, fmt.Sprintf("%x.data", sha256.Sum256([]byte(url))))
	if i.cacheDir != "" {
		cached, err := os.ReadFile(cachePath)
		if err == nil {
			return cached, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read source cache: %w", err)
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("construct request: %w", err)
	}
	request.Header.Set("User-Agent", "fphttp-primary-release-inventory")
	request.Header.Set("Accept", "application/json, text/plain, text/html")

	response, err := i.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(data) > responseLimit {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", url, responseLimit)
	}
	if i.cacheDir != "" {
		if err := os.MkdirAll(i.cacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("create source cache: %w", err)
		}
		if err := os.WriteFile(cachePath, data, 0o644); err != nil {
			return nil, fmt.Errorf("cache source: %w", err)
		}
	}

	return data, nil
}

func fetchJSON[T any](ctx context.Context, i *importer, url string) (T, error) {
	var value T
	data, err := i.fetch(ctx, url)
	if err != nil {
		return value, err
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return value, fmt.Errorf("decode %s: %w", url, err)
	}

	return value, nil
}

func (i *importer) includes(released time.Time) bool {
	return !released.Before(i.since) && released.Before(i.through)
}

func inventoryEntry(browserID httpfp.Browser, platform httpfp.Platform, version, engine, channel string, released time.Time, source browser.Source) browser.Descriptor {
	return browser.Descriptor{
		ID:            string(browserID) + "/" + string(platform) + "/" + version + "/" + channel + "/source-default",
		Browser:       browserID,
		Version:       version,
		EngineVersion: engine,
		Platform:      platform,
		Variant:       "source-default",
		Channel:       channel,
		Released:      released.UTC().Format(time.DateOnly),
		Coverage: browser.Coverage{
			TLS:     browser.EvidenceUnavailable,
			HTTP1:   browser.EvidenceUnavailable,
			HTTP2:   browser.EvidenceUnavailable,
			Headers: browser.EvidenceUnavailable,
		},
		Sources: []browser.Source{source},
		Limitations: []string{
			"Release inventory only; this build does not yet have a reviewed TLS/H2 definition.",
		},
	}
}

func numericVersion(version string) bool {
	for _, part := range strings.Split(version, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}

	return true
}

func uniqueEntries(entries []browser.Descriptor) []browser.Descriptor {
	seen := make(map[string]int, len(entries))
	result := make([]browser.Descriptor, 0, len(entries))
	for _, entry := range entries {
		if index, ok := seen[entry.ID]; ok {
			result[index].Sources = append(result[index].Sources, entry.Sources...)
			continue
		}
		seen[entry.ID] = len(result)
		result = append(result, entry)
	}

	return result
}
