// Package browser provides versioned browser profiles with explicit provenance.
package browser

import (
	http "github.com/aarock1234/fphttp"
)

// Evidence describes the provenance of one layer of a profile.
type Evidence string

// Evidence values distinguish observations from source derivations and gaps.
const (
	EvidenceSourceDerived Evidence = "source-derived"
	EvidenceObserved      Evidence = "observed"
	EvidenceAssumed       Evidence = "assumed"
	EvidenceUnavailable   Evidence = "unavailable"
)

// Coverage records the source of each protocol configuration.
type Coverage struct {
	TLS     Evidence `json:"tls"`
	HTTP1   Evidence `json:"http1"`
	HTTP2   Evidence `json:"http2"`
	Headers Evidence `json:"headers"`
}

// Source identifies primary release metadata, source code, or capture evidence.
type Source struct {
	URL      string `json:"url"`
	Revision string `json:"revision,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Selector selects an exact published build or the latest catalogued release
// matching a numeric version prefix. Empty Version selects the latest release.
// Optional fields constrain the choice; unknown builds never select an alias.
type Selector struct {
	Browser  http.Browser
	Version  string
	Platform http.Platform
	OSBuild  string
	Device   string
	Variant  string
	Channel  string
}

// Descriptor records one release and configuration, including unavailable
// inventory entries. Version is the product version, not the engine version.
type Descriptor struct {
	ID                 string        `json:"id"`
	Browser            http.Browser  `json:"browser"`
	Version            string        `json:"version"`
	EngineVersion      string        `json:"engine_version,omitempty"`
	Platform           http.Platform `json:"platform"`
	OSBuild            string        `json:"os_build,omitempty"`
	UserAgentOSVersion string        `json:"user_agent_os_version,omitempty"`
	Device             string        `json:"device,omitempty"`
	Variant            string        `json:"variant"`
	Channel            string        `json:"channel"`
	Released           string        `json:"released"`
	Coverage           Coverage      `json:"coverage"`
	Sources            []Source      `json:"sources"`
	Limitations        []string      `json:"limitations,omitempty"`

	// Available reports whether this entry has a usable request fingerprint.
	Available bool `json:"available"`
}
