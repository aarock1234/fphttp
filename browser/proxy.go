package browser

import (
	"context"
	"fmt"
	"net/url"

	http "github.com/aarock1234/fphttp/v2"
)

type proxySelection struct {
	url *url.URL
}

type proxySelectionKey struct{}

// prepareProxy evaluates a configured selector once for this hop. The pool's
// selector reuses that decision when the underlying transport acquires a
// connection, avoiding a second call to a potentially stateful selector.
func prepareProxy(req, logical *http.Request, pool *http.Transport, state *requestState) (*http.Request, error) {
	if pool.Proxy == nil {
		return req, nil
	}
	selected, err := pool.Proxy(req)
	if err != nil {
		return nil, fmt.Errorf("browser: select request proxy: %w", err)
	}
	if selected != nil {
		clone := *selected
		selected = &clone
	}
	ctx := context.WithValue(req.Context(), proxySelectionKey{}, proxySelection{url: selected})
	req = req.WithContext(ctx)

	plainHTTPProxy := selected != nil && (selected.Scheme == "http" || selected.Scheme == "https") && req.URL.Scheme == "http"
	if !plainHTTPProxy || state.disable || req.Close || !chromiumClientHints(state.profile) {
		return req, nil
	}
	if explicit, _ := requestHeader(logical.Header, "Connection"); explicit {
		return req, nil
	}
	req.Header.Del("Connection")
	setMissingHeader(req.Header, "Proxy-Connection", "keep-alive")

	return req, nil
}

func selectedProxy(selector func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if selection, ok := req.Context().Value(proxySelectionKey{}).(proxySelection); ok {
			return selection.url, nil
		}

		return selector(req)
	}
}
