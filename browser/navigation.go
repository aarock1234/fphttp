package browser

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	http "github.com/aarock1234/fphttp"
)

type hintKey struct {
	profile string
	origin  string
}

func (c *Client) navigate(state *requestState) (*http.Response, error) {
	for {
		request, err := navigationAttempt(state)
		if err != nil {
			return nil, err
		}
		state.restart = false
		response, err := c.httpClient.Do(request)
		if err != nil {
			return response, err
		}
		if err := c.observeResponse(state, response); err != nil {
			_ = response.Body.Close()

			return nil, err
		}
		if !state.restart {
			return response, nil
		}
		_ = response.Body.Close()
		state.restarts++
	}
}

func navigationAttempt(state *requestState) (*http.Request, error) {
	request := state.original.Clone(state.original.Context())
	if state.restarts == 0 || request.Body == nil || request.Body == http.NoBody {
		return request, nil
	}
	if request.GetBody == nil {
		return nil, errors.New("browser: navigation body cannot be replayed")
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, fmt.Errorf("browser: replay navigation body: %w", err)
	}
	if body == nil {
		return nil, errors.New("browser: GetBody returned a nil navigation body")
	}
	request.Body = body

	return request, nil
}

func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	state, ok := req.Context().Value(requestStateKey{}).(*requestState)
	if ok && c.config.Jar != nil {
		removeReplacedRedirectCookies(req, state)
	}
	if policy := c.config.CheckRedirect; policy != nil {
		referrerPresent, referrerValues := requestHeader(req.Header, "Referer")
		referrerValues = slices.Clone(referrerValues)
		if err := policy(req, via); err != nil {
			return err
		}
		present, values := requestHeader(req.Header, "Referer")
		if present && (!referrerPresent || !slices.Equal(referrerValues, values)) {
			ctx := context.WithValue(req.Context(), explicitRedirectReferrerKey{}, true)
			*req = *req.WithContext(ctx)
		}
	} else if len(via) >= 10 {
		return errors.New("browser: stopped after ten redirects")
	}

	if !ok || req.Response == nil {
		return nil
	}
	if err := c.observeResponse(state, req.Response); err != nil {
		return err
	}
	if state.restart {
		// The standard client preserves the response body for this sentinel.
		// The outer navigation owner closes it and restarts the original URL.
		return http.ErrUseLastResponse
	}

	return nil
}

func (c *Client) observeResponse(state *requestState, response *http.Response) error {
	if state.lastProcessed == response {
		return nil
	}
	state.lastProcessed = response
	if response.Request == nil {
		return nil
	}
	key := hintKey{
		profile: state.profile.descriptor.ID,
		origin:  headerOrigin(response.Request.URL),
	}
	if key.origin == "" {
		return nil
	}
	if clearSiteDataClientHints(response, state.metadata, state.profile) {
		c.mu.Lock()
		delete(c.hints, key)
		c.mu.Unlock()

		return nil
	}
	if state.disable {
		return nil
	}
	if !state.metadata.IsNavigation() {
		return nil
	}
	if !headerTrustworthy(response.Request.URL) {
		return nil
	}
	values, present := response.Header["Accept-Ch"]
	if !present {
		return nil
	}
	accepted, valid := parseClientHintList(values)
	if !valid {
		return nil
	}
	c.mu.Lock()
	c.hints[key] = slices.Clone(accepted)
	c.mu.Unlock()

	if state.origins[key.origin] || state.restarts >= c.config.MaxHintRestarts {
		return nil
	}
	if !canRestartNavigation(state) {
		return nil
	}
	critical := parseClientHints(response.Header.Values("Critical-CH"))
	if len(critical) == 0 {
		return nil
	}
	permitted := allowedClientHints(state.profile, response.Request, state.metadata, accepted)
	candidate, err := prepareHeaders(response.Request, state.profile, state.metadata, permitted, false)
	if err != nil {
		return err
	}
	for _, name := range critical {
		if !containsHint(accepted, name) || !containsHint(permitted, name) {
			continue
		}
		if candidate.Header.Get(name) != "" && response.Request.Header.Get(name) == "" {
			state.origins[key.origin] = true
			state.restart = true

			return nil
		}
	}

	return nil
}

func canRestartNavigation(state *requestState) bool {
	request := state.original
	if request.Method != "" && request.Method != http.MethodGet && request.Method != http.MethodHead && !state.allowReplay {
		return false
	}

	return request.Body == nil || request.Body == http.NoBody || request.GetBody != nil
}

func containsHint(hints []string, name string) bool {
	for _, hint := range hints {
		if strings.EqualFold(hint, name) {
			return true
		}
	}

	return false
}

func (c *Client) acceptedHints(profile *Profile, req *http.Request) []string {
	key := hintKey{
		profile: profile.descriptor.ID,
		origin:  headerOrigin(req.URL),
	}
	c.mu.Lock()
	hints := slices.Clone(c.hints[key])
	c.mu.Unlock()

	return hints
}
