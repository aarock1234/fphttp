package http

import "slices"

// checkRedirectHop runs the Client's redirect policy for a redirect hop
// whose Referer the Client may have generated (see Request.clientReferer).
// When CheckRedirect changes or removes that Referer, the field is the
// caller's choice, so the hop no longer counts as carrying a
// Client-generated Referer. Setting the same value again is not a change.
func (c *Client) checkRedirectHop(req *Request, via []*Request) error {
	if !req.clientReferer {
		return c.checkRedirect(req, via)
	}

	generated := slices.Clone(req.Header["Referer"])
	err := c.checkRedirect(req, via)

	if !slices.Equal(req.Header["Referer"], generated) {
		req.clientReferer = false
	}

	return err
}
