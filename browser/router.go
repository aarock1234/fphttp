package browser

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"

	http "github.com/aarock1234/fphttp/v2"
)

type routingTransport struct {
	client *Client
}

type explicitRedirectReferrerKey struct{}

func (r routingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	state, ok := req.Context().Value(requestStateKey{}).(*requestState)
	if !ok {
		closeRequestBody(req)

		return nil, errors.New("browser: request has no identity selection")
	}
	logical := req.Clone(req.Context())
	applyDefaultOverrides(logical, r.client.config.DefaultHeaders, state)
	clearGeneratedReferrer(logical, state, r.client.config.DefaultHeaders)
	hints := r.client.acceptedHints(state.profile, logical)
	prepared, err := prepareHeaders(logical, state.profile, state.metadata, hints, state.disable)
	if err != nil {
		closeRequestBody(req)

		return nil, err
	}
	if r.client.config.Fingerprint != nil {
		// A manual fingerprint owns wire layout and legacy priority. Context
		// still supplies ordinary header values unless the caller overrides them.
		prepared.HeaderOrder = logical.HeaderOrder
		prepared.H2Priority = logical.H2Priority
		prepared.H1HeaderCase = logical.H1HeaderCase
	}
	if automaticCookiesAllowed(state.metadata, prepared) {
		r.client.applyCookies(prepared)
	}
	pool, err := r.client.pool(state.profile)
	if err != nil {
		closeRequestBody(req)

		return nil, err
	}
	prepared, err = prepareProxy(prepared, logical, pool, state)
	if err != nil {
		closeRequestBody(req)

		return nil, err
	}
	response, err := pool.RoundTrip(prepared)
	if err != nil {
		return response, err
	}
	response.Request = prepared
	if automaticCookiesAllowed(state.metadata, prepared) {
		if err := r.client.storeCookies(response); err != nil {
			_ = response.Body.Close()

			return nil, fmt.Errorf("browser: store response cookies: %w", err)
		}
	}

	return response, nil
}

func clearGeneratedReferrer(req *http.Request, state *requestState, defaults http.Header) {
	if state.metadata == nil || req.Response == nil {
		return
	}
	if explicit, _ := req.Context().Value(explicitRedirectReferrerKey{}).(bool); explicit {
		return
	}
	if present, _ := requestHeader(state.original.Header, "Referer"); present {
		return
	}
	if present, _ := requestHeader(defaults, "Referer"); present {
		return
	}
	req.Header.Del("Referer")
}

func closeRequestBody(req *http.Request) {
	if req != nil && req.Body != nil {
		_ = req.Body.Close()
	}
}

func applyDefaultOverrides(req *http.Request, defaults http.Header, state *requestState) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	for name, values := range defaults {
		if sensitiveDefaultHeader(name) && !redirectDefaultsAllowed(req, state.original) {
			continue
		}
		if present, _ := requestHeader(req.Header, name); !present {
			req.Header[name] = slices.Clone(values)
		}
	}
}

func sensitiveDefaultHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "proxy-authenticate", "www-authenticate", "cookie", "cookie2":
		return true
	default:
		return false
	}
}

func redirectDefaultsAllowed(req, original *http.Request) bool {
	if req.Response == nil {
		return true
	}
	parent, err := httpguts.PunycodeHostPort(original.URL.Hostname())
	if err != nil {
		return false
	}
	parent = strings.ToLower(parent)
	for current := req; current != nil; {
		host, err := httpguts.PunycodeHostPort(current.URL.Hostname())
		if err != nil {
			return false
		}
		host = strings.ToLower(host)
		if host != parent && (strings.ContainsAny(host, ":%") || !strings.HasSuffix(host, "."+parent)) {
			return false
		}
		if current.Response == nil {
			break
		}
		current = current.Response.Request
	}

	return true
}
