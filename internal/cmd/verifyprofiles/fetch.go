package main

import "github.com/aarock1234/fphttp/v2/internal/releasefetch"

const (
	// responseLimit bounds one response body. The largest source file read,
	// Firefox's StaticPrefList.yaml, is under 1 MiB.
	responseLimit = 32 << 20

	// userAgent identifies this tool to source hosts.
	userAgent = "fphttp-verifyprofiles"
)

// newFetcher returns a fetcher for browser source files that caches
// responses in cacheDir, or caches nothing when cacheDir is empty.
func newFetcher(cacheDir string) *releasefetch.Fetcher {
	return releasefetch.New(releasefetch.Config{
		CacheDir:      cacheDir,
		UserAgent:     userAgent,
		ResponseLimit: responseLimit,
	})
}
