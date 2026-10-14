package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const (
	// fetchConcurrency bounds the network requests in flight across every
	// collector.
	fetchConcurrency = 8

	// requestTimeout bounds one request, including reading its body.
	requestTimeout = 2 * time.Minute

	// responseLimit bounds one response body. The largest feed, Mozilla's
	// Firefox product details, is under 1 MiB.
	responseLimit = 16 << 20

	// userAgent identifies this tool to feed servers.
	userAgent = "fphttp-syncprofiles"
)

// fetcher downloads release feeds. It bounds concurrent network requests and
// keeps every successful response in an on-disk cache that later runs trust
// without revalidation.
type fetcher struct {
	client *http.Client

	// cacheDir holds cached responses; "" disables caching.
	cacheDir string

	requests semaphore
}

// statusError reports a response whose status is not 200 OK.
type statusError struct {
	url    string
	status string
	code   int
}

// Error describes the request and the status it received.
func (e *statusError) Error() string {
	return fmt.Sprintf("fetch %s: unexpected status %s", e.url, e.status)
}

// isNotFound reports whether err comes from a 404 Not Found response.
func isNotFound(err error) bool {
	statusErr, ok := errors.AsType[*statusError](err)

	return ok && statusErr.code == http.StatusNotFound
}

// newFetcher returns a fetcher that caches responses in cacheDir, or caches
// nothing when cacheDir is empty.
func newFetcher(cacheDir string) *fetcher {
	return &fetcher{
		client:   &http.Client{},
		cacheDir: cacheDir,
		requests: make(semaphore, fetchConcurrency),
	}
}

// fetch returns the body of a successful GET request for rawURL, reading the
// cache first and filling it after a download.
func (f *fetcher) fetch(ctx context.Context, rawURL string) ([]byte, error) {
	cached, found, err := f.readCache(rawURL)
	if err != nil {
		return nil, err
	}

	if found {
		return cached, nil
	}

	body, err := f.download(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	if err := f.writeCache(rawURL, body); err != nil {
		slog.Warn("caching response failed",
			slog.String("url", rawURL),
			slog.Any("error", err),
		)
	}

	return body, nil
}

// fetchText returns the body of rawURL as text.
func (f *fetcher) fetchText(ctx context.Context, rawURL string) (string, error) {
	body, err := f.fetch(ctx, rawURL)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// fetchJSON decodes the JSON body of rawURL into a T.
func (f *fetcher) fetchJSON[T any](ctx context.Context, rawURL string) (T, error) {
	var value T

	body, err := f.fetch(ctx, rawURL)
	if err != nil {
		return value, err
	}

	if err := json.Unmarshal(body, &value); err != nil {
		return value, fmt.Errorf("decode %s: %w", rawURL, err)
	}

	return value, nil
}

// download performs one bounded GET request for rawURL. A response other
// than 200 OK fails with a *statusError.
func (f *fetcher) download(ctx context.Context, rawURL string) ([]byte, error) {
	if err := f.requests.acquire(ctx); err != nil {
		return nil, err
	}
	defer f.requests.release()

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	request, err := newRequest(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	response, err := f.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, &statusError{
			url:    rawURL,
			status: response.Status,
			code:   response.StatusCode,
		}
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rawURL, err)
	}

	if len(body) > responseLimit {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", rawURL, responseLimit)
	}

	return body, nil
}

// newRequest builds a GET request for rawURL.
func newRequest(ctx context.Context, rawURL string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", rawURL, err)
	}

	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "application/json, text/plain, text/html")

	return request, nil
}

// cachePath returns the cache file for rawURL: the hex SHA-256 of the URL
// with a .data extension, the layout earlier runs of this tool wrote.
func (f *fetcher) cachePath(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))

	return filepath.Join(f.cacheDir, hex.EncodeToString(sum[:])+".data")
}

// readCache returns the cached body of rawURL and whether one was found.
func (f *fetcher) readCache(rawURL string) ([]byte, bool, error) {
	if f.cacheDir == "" {
		return nil, false, nil
	}

	body, err := os.ReadFile(f.cachePath(rawURL))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, fmt.Errorf("read cached response: %w", err)
	}

	return body, true, nil
}

// writeCache stores body as the cached response of rawURL.
func (f *fetcher) writeCache(rawURL string, body []byte) error {
	if f.cacheDir == "" {
		return nil
	}

	if err := os.MkdirAll(f.cacheDir, 0o755); err != nil {
		return fmt.Errorf("create response cache: %w", err)
	}

	return replaceFile(f.cachePath(rawURL), body)
}
