// Package releasefetch downloads browser release feeds and source files for
// the catalog tools. It bounds concurrent requests and shares one on-disk
// response cache between syncprofiles and verifyprofiles.
//
// It imports only the standard library, so the tools still build while the
// generated catalog is broken.
package releasefetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	// requestConcurrency bounds the network requests in flight across every
	// caller of one Fetcher.
	requestConcurrency = 8

	// requestTimeout bounds one request, including reading its body.
	requestTimeout = 2 * time.Minute
)

// Config describes how a Fetcher identifies itself and where it caches
// responses.
type Config struct {
	// CacheDir holds cached responses; "" disables caching.
	CacheDir string

	// UserAgent identifies the tool to the servers it fetches from.
	UserAgent string

	// Accept is sent as the Accept header; "" sends none.
	Accept string

	// ResponseLimit bounds one response body in bytes.
	ResponseLimit int
}

// Fetcher downloads release feeds and source files. It bounds concurrent
// network requests and keeps every successful response in an on-disk cache
// that later runs trust without revalidation.
type Fetcher struct {
	client   *http.Client
	config   Config
	requests Semaphore
}

// StatusError reports a response whose status is not 200 OK.
type StatusError struct {
	URL    string
	Status string
	Code   int
}

// Error describes the request and the status it received.
func (e *StatusError) Error() string {
	return fmt.Sprintf("fetch %s: unexpected status %s", e.URL, e.Status)
}

// IsNotFound reports whether err comes from a 404 Not Found response.
func IsNotFound(err error) bool {
	statusErr, ok := errors.AsType[*StatusError](err)

	return ok && statusErr.Code == http.StatusNotFound
}

// New returns a Fetcher configured by config.
func New(config Config) *Fetcher {
	return &Fetcher{
		client:   &http.Client{},
		config:   config,
		requests: NewSemaphore(requestConcurrency),
	}
}

// Fetch returns the body of a successful GET request for rawURL, reading the
// cache first and filling it after a download. A failure to fill the cache
// is logged and does not fail the fetch.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
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

// FetchText returns the body of rawURL as text.
func (f *Fetcher) FetchText(ctx context.Context, rawURL string) (string, error) {
	body, err := f.Fetch(ctx, rawURL)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// FetchJSON decodes the JSON body of rawURL into a T.
func (f *Fetcher) FetchJSON[T any](ctx context.Context, rawURL string) (T, error) {
	var value T

	body, err := f.Fetch(ctx, rawURL)
	if err != nil {
		return value, err
	}

	if err := json.Unmarshal(body, &value); err != nil {
		return value, fmt.Errorf("decode %s: %w", rawURL, err)
	}

	return value, nil
}

// download performs one bounded GET request for rawURL. A response other
// than 200 OK fails with a *StatusError.
func (f *Fetcher) download(ctx context.Context, rawURL string) ([]byte, error) {
	if err := f.requests.Acquire(ctx); err != nil {
		return nil, err
	}
	defer f.requests.Release()

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	request, err := f.newRequest(ctx, rawURL)
	if err != nil {
		return nil, err
	}

	response, err := f.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, &StatusError{
			URL:    rawURL,
			Status: response.Status,
			Code:   response.StatusCode,
		}
	}

	return f.readBody(rawURL, response.Body)
}

// newRequest builds a GET request for rawURL with the configured headers.
func (f *Fetcher) newRequest(ctx context.Context, rawURL string) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request for %s: %w", rawURL, err)
	}

	request.Header.Set("User-Agent", f.config.UserAgent)

	if f.config.Accept != "" {
		request.Header.Set("Accept", f.config.Accept)
	}

	return request, nil
}

// readBody reads a response body, failing when it exceeds the configured
// limit.
func (f *Fetcher) readBody(rawURL string, body io.Reader) ([]byte, error) {
	limit := f.config.ResponseLimit

	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", rawURL, err)
	}

	if len(data) > limit {
		return nil, fmt.Errorf("fetch %s: response exceeds %d bytes", rawURL, limit)
	}

	return data, nil
}
