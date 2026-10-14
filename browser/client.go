package browser

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	http "github.com/aarock1234/fphttp/v2"
)

// CookiePolicy supplies application-specific cookie serialization and storage.
// Methods may be called concurrently. ApplyCookies receives a private request.
// StoreCookies must not read or close the response body.
type CookiePolicy interface {
	ApplyCookies(*http.Request)
	StoreCookies(*http.Response) error
}

// Config configures a browser client. New snapshots headers, wire settings,
// and transport configuration. Jars, callbacks, and custom TLS templates retain
// their documented ownership contracts.
type Config struct {
	// Profile selects the default identity. Nil selects the catalog's latest
	// Chrome release on Windows, without consulting the running machine.
	Profile *Profile

	// Transport is cloned for each identity. Nil uses DefaultTransport.
	Transport *http.Transport

	// Fingerprint deliberately overrides the catalog's wire configuration.
	// It does not change identity headers or establish catalog equivalence.
	// Browser clients allocate their own session cache for each identity.
	// Automatic contextual layout and legacy priority overrides are disabled.
	Fingerprint *http.Fingerprint

	// DefaultHeaders overrides managed defaults. Present empty values suppress
	// a field; deleting it restores generation. Request headers take precedence.
	DefaultHeaders http.Header

	// Timeout bounds the complete operation, including redirects, hint
	// restarts, and reading the returned response body. Zero has no time limit.
	Timeout time.Duration

	// Jar supplies ordinary cookies. Application and storage follow contextual
	// credentials mode. Nonempty explicit Cookie values precede jar cookies;
	// an empty Cookie field suppresses automatic application. Jar cannot
	// accompany CookiePolicy.
	Jar http.CookieJar

	// CookiePolicy replaces ordinary jar handling when custom serialization
	// or response extraction is required. Application and storage follow
	// contextual credentials mode. An empty Cookie field suppresses application;
	// otherwise the policy owns merging with explicit Cookie values.
	CookiePolicy CookiePolicy

	// CheckRedirect applies the ordinary fphttp redirect policy. Nil limits
	// each redirect chain to ten requests.
	CheckRedirect func(*http.Request, []*http.Request) error

	// DisableHeaders disables browser-generated fields. Explicit headers remain.
	DisableHeaders bool

	// DisableDecompression leaves response bodies in their encoded form.
	DisableDecompression bool

	// MaxHintRestarts bounds Critical-CH navigation restarts. Zero uses ten.
	MaxHintRestarts int
}

// RequestOptions overrides the identity or browser context for one operation.
type RequestOptions struct {
	// Profile overrides the client's default identity without sharing its pool.
	Profile *Profile

	// Context supplies browser request semantics. Nil generates basic identity
	// fields only and does not assume a navigation or a script fetch.
	Context *RequestContext

	// DisableHeaders disables managed headers for this operation.
	DisableHeaders bool

	// AllowReplay permits Critical-CH to restart navigation methods other than
	// GET and HEAD. A body must still have a working GetBody callback.
	AllowReplay bool
}

// Client manages browser identity, connection pools, and contextual client hints.
// It is safe for concurrent use. Returned response bodies belong to the caller.
type Client struct {
	config     Config
	profile    *Profile
	template   *http.Transport
	httpClient *http.Client

	mu    sync.Mutex
	pools map[string]*http.Transport
	hints map[hintKey][]string
}

type requestState struct {
	profile         *Profile
	metadata        *RequestContext
	disable         bool
	allowReplay     bool
	original        *http.Request
	lastProcessed   *http.Response
	restart         bool
	restarts        int
	origins         map[string]bool
	replacedCookies map[string]bool
}

type requestStateKey struct{}

// New creates a browser-aware client. Caller headers override managed values;
// explicit empty values suppress them. Such overrides can change fingerprint
// consistency. Use the low-level fphttp APIs for unrestricted wire configuration.
func New(config Config) (*Client, error) {
	if config.Timeout < 0 || config.MaxHintRestarts < 0 {
		return nil, errors.New("browser: timeout and hint restart limit must not be negative")
	}
	if config.Jar != nil && config.CookiePolicy != nil {
		return nil, errors.New("browser: configure either Jar or CookiePolicy")
	}
	if config.MaxHintRestarts == 0 {
		config.MaxHintRestarts = 10
	}
	if config.Fingerprint != nil {
		if config.Fingerprint.ClientSessionCache != nil {
			return nil, errors.New("browser: session caches belong to individual profile pools; remove the fingerprint's shared cache")
		}
		if err := config.Fingerprint.Validate(); err != nil {
			return nil, fmt.Errorf("browser: validate manual fingerprint: %w", err)
		}
		config.Fingerprint = config.Fingerprint.Clone()
	}
	config.DefaultHeaders = config.DefaultHeaders.Clone()
	if err := normalizeManagedHeaders(config.DefaultHeaders); err != nil {
		return nil, err
	}

	profile := config.Profile
	if profile == nil {
		var err error
		profile, err = Resolve(Selector{
			Browser:  http.BrowserChrome,
			Platform: http.PlatformWindows,
		})
		if err != nil {
			return nil, err
		}
	}
	if profile.Fingerprint() == nil && config.Fingerprint == nil {
		return nil, errors.New("browser: profile has no executable TLS/HTTP2 definition")
	}

	template := config.Transport
	if template == nil {
		var ok bool
		template, ok = http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, errors.New("browser: provide a transport template when DefaultTransport is not an fphttp Transport")
		}
	}

	c := &Client{
		config:   config,
		profile:  profile,
		template: template.Clone(),
		pools:    make(map[string]*http.Transport),
		hints:    make(map[hintKey][]string),
	}
	c.httpClient = &http.Client{
		Transport:     routingTransport{client: c},
		CheckRedirect: c.checkRedirect,
	}

	return c, nil
}

// Do sends req using the client's default profile and basic identity headers.
// It does not modify req. The caller must close the returned response body.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.DoWithOptions(req, RequestOptions{})
}

// DoWithOptions sends req using explicit browser context and optional identity.
// Managed fields are regenerated for each hop. A single deadline covers all
// redirects, eligible hint restarts, and reading the final response body.
func (c *Client) DoWithOptions(req *http.Request, options RequestOptions) (*http.Response, error) {
	if req == nil || req.URL == nil {
		closeRequestBody(req)

		return nil, errors.New("browser: request and URL must not be nil")
	}
	profile := options.Profile
	if profile == nil {
		profile = c.profile
	}
	if profile.Fingerprint() == nil && c.config.Fingerprint == nil {
		closeRequestBody(req)

		return nil, errors.New("browser: selected profile has no executable TLS/HTTP2 definition")
	}
	state := &requestState{
		profile:         profile,
		metadata:        options.Context.Clone(),
		disable:         c.config.DisableHeaders || options.DisableHeaders,
		allowReplay:     options.AllowReplay,
		origins:         make(map[string]bool),
		replacedCookies: make(map[string]bool),
	}
	ctx, cancel := c.operationContext(req.Context())
	ctx = context.WithValue(ctx, requestStateKey{}, state)
	state.original = req.Clone(ctx)

	response, err := c.navigate(state)
	if err != nil {
		cancel()

		return response, err
	}
	if !c.config.DisableDecompression {
		if err := decodeResponse(response); err != nil {
			_ = response.Body.Close()
			cancel()

			return nil, err
		}
	}
	response.Body = &operationBody{
		ReadCloser: response.Body,
		cancel:     cancel,
	}

	return response, nil
}

func (c *Client) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.config.Timeout > 0 {
		return context.WithTimeout(ctx, c.config.Timeout)
	}

	return context.WithCancel(ctx)
}

// CloseIdleConnections closes idle connections in every selected profile pool.
// Active requests and caller-owned response bodies are not interrupted.
func (c *Client) CloseIdleConnections() {
	c.mu.Lock()
	pools := make([]*http.Transport, 0, len(c.pools))
	for _, pool := range c.pools {
		pools = append(pools, pool)
	}
	c.mu.Unlock()

	for _, pool := range pools {
		pool.CloseIdleConnections()
	}
}

// ClearClientHints clears learned hints for every identity. Call it when clearing
// externally managed cookies or site state; individual cookie expiry is not a
// signal that an entire browsing session has been cleared.
func (c *Client) ClearClientHints() {
	c.mu.Lock()
	clear(c.hints)
	c.mu.Unlock()
}
