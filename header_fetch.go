package http

import "net/url"

// fetchMetadata adds the Sec-Fetch-* fields, which browsers send only to
// potentially trustworthy URLs: Sec-Fetch-Site (see secFetchSite),
// Sec-Fetch-Mode and Sec-Fetch-Dest from the Destination, and
// Sec-Fetch-User where the release sends it, on top-level page loads.
func (g *fieldGenerator) fetchMetadata() {
	if !g.trustworthy() {
		return
	}

	destination := g.request.Destination

	g.addMissing("Sec-Fetch-Site", secFetchSite(g.request.Initiator, g.chain))
	g.addMissing("Sec-Fetch-Mode", string(destination.mode()))
	g.addMissing("Sec-Fetch-User", g.entry.SecFetchUser(g.destination()))
	g.addMissing("Sec-Fetch-Dest", destination.secFetchDest())
}

// secFetchSite returns the Sec-Fetch-Site value of a request started by
// initiator whose redirect chain, oldest first, is chain: "none" when the
// user started it (a nil initiator), and otherwise the farthest relation
// between the initiator and any URL of the chain, so a request redirected
// through another site stays cross-site.
func secFetchSite(initiator *url.URL, chain []*Request) string {
	if initiator == nil {
		return "none"
	}

	relation := relationSameOrigin
	for _, hop := range chain {
		relation = max(relation, relationBetween(initiator, hop.URL))
	}

	return relation.secFetchSite()
}
