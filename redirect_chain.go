package http

import "slices"

// redirectChain returns the requests of r's redirect chain, oldest first and
// ending with r.
//
// A Client links each redirect hop to the response that caused it through
// Request.Response, and the Transport sets that response's Request to the
// hop it answered, so the chain carries every hop's URL and every redirect
// response. For i > 0, chain[i].Response is the response to chain[i-1]. A
// request that is not a redirect hop is a chain of its own.
func (r *Request) redirectChain() []*Request {
	chain := []*Request{r}
	hop := r

	for hop.Response != nil && hop.Response.Request != nil {
		hop = hop.Response.Request
		chain = append(chain, hop)
	}

	slices.Reverse(chain)

	return chain
}
