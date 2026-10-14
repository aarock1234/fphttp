package http2

import (
	"maps"
	"net/textproto"
	"slices"
	"strings"
)

func requestHeadersWithPriority(req *ClientRequest, headerOrder []string) (Header, []string) {
	if req.H2PriorityHeader == "" {
		return req.Header, headerOrder
	}
	for name := range req.Header {
		if strings.EqualFold(name, "Priority") {
			return req.Header, headerOrder
		}
	}

	headers := maps.Clone(req.Header)
	if headers == nil {
		headers = make(Header)
	}
	headers["Priority"] = []string{req.H2PriorityHeader}

	return headers, priorityHeaderOrder(headers, headerOrder)
}

func priorityHeaderOrder(headers Header, headerOrder []string) []string {
	listed := make(map[string]bool, len(headerOrder))
	for _, name := range headerOrder {
		if strings.EqualFold(name, "Priority") {
			return headerOrder
		}
		listed[strings.ToLower(name)] = true
	}

	var unlisted []string
	addName := func(name string) {
		if strings.HasPrefix(name, ":") || strings.EqualFold(name, "Priority") {
			return
		}
		key := strings.ToLower(name)
		if listed[key] {
			return
		}
		listed[key] = true
		unlisted = append(unlisted, textproto.CanonicalMIMEHeaderKey(name))
	}
	for name := range headers {
		addName(name)
	}

	// EncodeHeaders can add these fields outside the request's Header map.
	// Reserving their positions keeps generated Priority last when they appear.
	for _, name := range []string{"Accept-Encoding", "Content-Length", "Trailer", "User-Agent"} {
		addName(name)
	}
	slices.Sort(unlisted)

	order := slices.Clone(headerOrder)
	order = append(order, unlisted...)
	order = append(order, "Priority")

	return order
}
