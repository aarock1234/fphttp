package browser

import (
	"slices"
	"strings"

	http "github.com/aarock1234/fphttp"
)

func (c *Client) applyCookies(req *http.Request) {
	if present, values := requestHeader(req.Header, "Cookie"); present && headerSuppressed(values) {
		return
	}
	if c.config.CookiePolicy != nil {
		c.config.CookiePolicy.ApplyCookies(req)

		return
	}
	if c.config.Jar != nil {
		for _, cookie := range c.config.Jar.Cookies(req.URL) {
			req.AddCookie(cookie)
		}
	}
}

func removeReplacedRedirectCookies(req *http.Request, state *requestState) {
	response := req.Response
	if response == nil || response.Request == nil {
		return
	}
	if automaticCookiesAllowed(state.metadata, response.Request) {
		for _, cookie := range response.Cookies() {
			state.replacedCookies[cookie.Name] = true
		}
	}
	if len(state.replacedCookies) == 0 || req.Header.Get("Cookie") == "" {
		return
	}

	var values []string
	changed := false
	for _, cookie := range req.Cookies() {
		if state.replacedCookies[cookie.Name] {
			changed = true
			continue
		}
		values = append(values, cookie.Name+"="+cookie.Value)
	}
	if !changed {
		return
	}
	slices.Sort(values)
	req.Header.Set("Cookie", strings.Join(values, "; "))
}

func (c *Client) storeCookies(response *http.Response) error {
	if c.config.CookiePolicy != nil {
		return c.config.CookiePolicy.StoreCookies(response)
	}
	if c.config.Jar != nil {
		if cookies := response.Cookies(); len(cookies) > 0 {
			c.config.Jar.SetCookies(response.Request.URL, cookies)
		}
	}

	return nil
}

func automaticCookiesAllowed(metadata *RequestContext, req *http.Request) bool {
	if metadata == nil {
		return true
	}
	switch metadata.credentialsMode() {
	case CredentialsOmit:
		return false
	case CredentialsSameOrigin:
		return sameHeaderOrigin(metadata.Initiator, req.URL)
	default:
		return true
	}
}
