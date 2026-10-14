package http2

// This file is fphttp-only.

// ResponseHeaderListLimit returns the largest response header list, in
// HPACK size units, that a Transport built from t1 accepts, or 0 when it
// sets no limit. A connection enforces the smaller of this limit and the
// MAX_HEADER_LIST_SIZE its profile advertises, so the root package checks
// that a profile never advertises more than the Transport accepts.
func ResponseHeaderListLimit(t1 TransportConfig) uint32 {
	transport := &Transport{
		t1: t1,
	}

	return transport.maxHeaderListSize()
}
