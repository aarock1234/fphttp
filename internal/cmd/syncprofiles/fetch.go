package main

import "github.com/aarock1234/fphttp/v2/internal/releasefetch"

const (
	// responseLimit bounds one response body. The largest feed, Mozilla's
	// Firefox product details, is under 1 MiB.
	responseLimit = 16 << 20

	// userAgent identifies this tool to feed servers.
	userAgent = "fphttp-syncprofiles"

	// acceptedTypes lists the feed formats this tool reads.
	acceptedTypes = "application/json, text/plain, text/html"
)

// newFetcher returns a fetcher for release feeds that caches responses in
// cacheDir, or caches nothing when cacheDir is empty.
func newFetcher(cacheDir string) *releasefetch.Fetcher {
	return releasefetch.New(releasefetch.Config{
		CacheDir:      cacheDir,
		UserAgent:     userAgent,
		Accept:        acceptedTypes,
		ResponseLimit: responseLimit,
	})
}
