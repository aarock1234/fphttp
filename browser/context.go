package browser

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// RequestKind identifies the browser operation that produced a request.
type RequestKind string

const (
	// Navigation identifies a top-level document navigation.
	Navigation RequestKind = "navigation"

	// Fetch identifies a JavaScript fetch with an empty destination.
	Fetch RequestKind = "fetch"

	// Resource identifies a subresource with an explicit destination.
	Resource RequestKind = "resource"
)

// FetchMode identifies the Fetch request mode used in fetch metadata.
type FetchMode string

const (
	// ModeCORS is the default mode for JavaScript fetch.
	ModeCORS FetchMode = "cors"

	// ModeNoCORS identifies an opaque subresource request.
	ModeNoCORS FetchMode = "no-cors"

	// ModeSameOrigin restricts the request to its initiating origin.
	ModeSameOrigin FetchMode = "same-origin"

	// ModeNavigate identifies a document navigation.
	ModeNavigate FetchMode = "navigate"
)

// CredentialsMode describes whether a browser operation uses credentials.
type CredentialsMode string

const (
	// CredentialsDefault uses include for navigation and ordinary resources,
	// and same-origin for JavaScript fetch.
	CredentialsDefault CredentialsMode = ""

	// CredentialsOmit excludes credentials.
	CredentialsOmit CredentialsMode = "omit"

	// CredentialsSameOrigin uses credentials only on the initiating origin.
	CredentialsSameOrigin CredentialsMode = "same-origin"

	// CredentialsInclude allows credentials on the destination origin.
	CredentialsInclude CredentialsMode = "include"
)

// CacheMode identifies explicit browser cache operations.
type CacheMode string

const (
	// CacheDefault does not add a cache directive.
	CacheDefault CacheMode = ""

	// CacheReload requests validation of an existing cached response.
	CacheReload CacheMode = "reload"

	// CacheNoCache bypasses an existing cached response.
	CacheNoCache CacheMode = "no-cache"
)

// ReferrerPolicy controls the information included in Referer.
type ReferrerPolicy string

const (
	// ReferrerDefault uses strict-origin-when-cross-origin.
	ReferrerDefault ReferrerPolicy = ""

	// ReferrerNoReferrer omits Referer.
	ReferrerNoReferrer ReferrerPolicy = "no-referrer"

	// ReferrerNoReferrerWhenDowngrade sends a full URL except on a downgrade.
	ReferrerNoReferrerWhenDowngrade ReferrerPolicy = "no-referrer-when-downgrade"

	// ReferrerOrigin sends only the origin.
	ReferrerOrigin ReferrerPolicy = "origin"

	// ReferrerOriginWhenCrossOrigin sends a full URL only on the same origin.
	ReferrerOriginWhenCrossOrigin ReferrerPolicy = "origin-when-cross-origin"

	// ReferrerSameOrigin omits Referer outside the initiating origin.
	ReferrerSameOrigin ReferrerPolicy = "same-origin"

	// ReferrerStrictOrigin omits an origin referrer on a downgrade.
	ReferrerStrictOrigin ReferrerPolicy = "strict-origin"

	// ReferrerStrictOriginWhenCrossOrigin is the modern browser default.
	ReferrerStrictOriginWhenCrossOrigin ReferrerPolicy = "strict-origin-when-cross-origin"

	// ReferrerUnsafeURL includes the full URL on every destination.
	ReferrerUnsafeURL ReferrerPolicy = "unsafe-url"
)

// DeviceMetadata supplies known device attributes for negotiated client hints.
// A nil field is unknown. A pointer to an empty string is a known empty value.
// PlatformVersion is the browser's hint value, not a raw operating system label;
// Windows, for example, uses its UniversalApiContract version.
type DeviceMetadata struct {
	Architecture       *string
	Bitness            *string
	PlatformVersion    *string
	Model              *string
	WoW64              *bool
	Mobile             *bool
	FormFactors        []string
	UserAgentOSVersion string
}

// Clone returns an independently owned copy of d, or nil when d is nil.
func (d *DeviceMetadata) Clone() *DeviceMetadata {
	if d == nil {
		return nil
	}

	clone := *d
	if d.Architecture != nil {
		clone.Architecture = new(*d.Architecture)
	}
	if d.Bitness != nil {
		clone.Bitness = new(*d.Bitness)
	}
	if d.PlatformVersion != nil {
		clone.PlatformVersion = new(*d.PlatformVersion)
	}
	if d.Model != nil {
		clone.Model = new(*d.Model)
	}
	if d.WoW64 != nil {
		clone.WoW64 = new(*d.WoW64)
	}
	if d.Mobile != nil {
		clone.Mobile = new(*d.Mobile)
	}
	clone.FormFactors = slices.Clone(d.FormFactors)

	return &clone
}

// RequestContext supplies browser state that cannot be inferred from a URL.
// A nil context generates basic identity headers only. Fetch and Resource
// require Initiator; Resource also requires Destination and Mode. Languages
// are an already expanded, ordered preference list; no local locale is read.
// AcceptLanguage supplies an exact value when the browser's formatting is not
// established. ClientHintPermissions maps hint field names to permitted origins;
// an empty list denies that hint, and "*" permits every origin.
type RequestContext struct {
	Kind                  RequestKind
	Initiator             *url.URL
	TopLevelOrigin        *url.URL
	Mode                  FetchMode
	Destination           string
	UserActivation        bool
	Credentials           CredentialsMode
	Referrer              *url.URL
	ReferrerPolicy        ReferrerPolicy
	Languages             []string
	AcceptLanguage        string
	CacheMode             CacheMode
	Device                *DeviceMetadata
	ClientHintPermissions map[string][]string
}

// Clone returns an independently owned copy of c, or nil when c is nil.
func (c *RequestContext) Clone() *RequestContext {
	if c == nil {
		return nil
	}

	clone := *c
	clone.Initiator = cloneContextURL(c.Initiator)
	clone.TopLevelOrigin = cloneContextURL(c.TopLevelOrigin)
	clone.Referrer = cloneContextURL(c.Referrer)
	clone.Languages = slices.Clone(c.Languages)
	clone.Device = c.Device.Clone()
	if c.ClientHintPermissions != nil {
		clone.ClientHintPermissions = make(map[string][]string, len(c.ClientHintPermissions))
		for name, origins := range c.ClientHintPermissions {
			clone.ClientHintPermissions[name] = slices.Clone(origins)
		}
	}

	return &clone
}

// IsNavigation reports whether c describes a top-level navigation.
func (c *RequestContext) IsNavigation() bool {
	return c != nil && c.Kind == Navigation
}

func (c *RequestContext) validate() error {
	if c == nil {
		return nil
	}

	switch c.Kind {
	case Navigation:
		if c.Mode != "" && c.Mode != ModeNavigate {
			return errors.New("browser: navigation requires navigate mode")
		}
		if c.Destination != "" && c.Destination != "document" {
			return errors.New("browser: top-level navigation requires document destination")
		}
	case Fetch:
		if c.Initiator == nil {
			return errors.New("browser: fetch context requires an initiator")
		}
		if c.Destination != "" && c.Destination != "empty" {
			return errors.New("browser: fetch context requires an empty destination")
		}
	case Resource:
		if c.Initiator == nil || c.Destination == "" || c.Mode == "" {
			return errors.New("browser: resource context requires initiator, destination, and mode")
		}
	default:
		return fmt.Errorf("browser: unsupported request kind %q", c.Kind)
	}

	if c.Mode != "" && c.Mode != ModeCORS && c.Mode != ModeNoCORS && c.Mode != ModeSameOrigin && c.Mode != ModeNavigate {
		return fmt.Errorf("browser: unsupported fetch mode %q", c.Mode)
	}
	if c.Kind != Navigation && c.Mode == ModeNavigate {
		return errors.New("browser: navigate mode requires navigation context")
	}
	if c.Kind == Resource && !validDestination(c.Destination) {
		return fmt.Errorf("browser: unsupported resource destination %q", c.Destination)
	}
	if !validCredentialsMode(c.Credentials) {
		return fmt.Errorf("browser: unsupported credentials mode %q", c.Credentials)
	}
	if c.CacheMode != CacheDefault && c.CacheMode != CacheReload && c.CacheMode != CacheNoCache {
		return fmt.Errorf("browser: unsupported cache mode %q", c.CacheMode)
	}
	if !validReferrerPolicy(c.ReferrerPolicy) {
		return fmt.Errorf("browser: unsupported referrer policy %q", c.ReferrerPolicy)
	}
	for _, value := range []*url.URL{c.Initiator, c.TopLevelOrigin, c.Referrer} {
		if value != nil && (value.Opaque != "" || headerOrigin(value) == "") {
			return errors.New("browser: context URLs require an HTTP or HTTPS origin")
		}
	}
	for _, language := range c.Languages {
		if language == "" || strings.ContainsAny(language, ",;\r\n\t ") {
			return errors.New("browser: invalid language preference")
		}
	}
	if strings.ContainsAny(c.AcceptLanguage, "\r\n") {
		return errors.New("browser: invalid Accept-Language value")
	}
	if err := validateHintPermissions(c.ClientHintPermissions); err != nil {
		return err
	}

	return nil
}

func (c *RequestContext) credentialsMode() CredentialsMode {
	if c == nil {
		return CredentialsOmit
	}
	if c.Credentials != CredentialsDefault {
		return c.Credentials
	}
	if c.Kind == Fetch {
		return CredentialsSameOrigin
	}

	return CredentialsInclude
}

func cloneContextURL(value *url.URL) *url.URL {
	if value == nil {
		return nil
	}

	clone := *value

	return &clone
}

func validDestination(value string) bool {
	switch value {
	case "audio", "audioworklet", "embed", "font", "frame", "iframe",
		"image", "manifest", "object", "paintworklet", "report", "script",
		"serviceworker", "sharedworker", "style", "track", "video", "worker", "xslt":
		return true
	default:
		return false
	}
}

func validReferrerPolicy(value ReferrerPolicy) bool {
	switch value {
	case ReferrerDefault, ReferrerNoReferrer, ReferrerNoReferrerWhenDowngrade,
		ReferrerOrigin, ReferrerOriginWhenCrossOrigin, ReferrerSameOrigin,
		ReferrerStrictOrigin, ReferrerStrictOriginWhenCrossOrigin, ReferrerUnsafeURL:
		return true
	default:
		return false
	}
}

func validCredentialsMode(value CredentialsMode) bool {
	switch value {
	case CredentialsDefault, CredentialsOmit, CredentialsSameOrigin, CredentialsInclude:
		return true
	default:
		return false
	}
}

func validateHintPermissions(permissions map[string][]string) error {
	seen := make(map[string]bool, len(permissions))
	for name, origins := range permissions {
		name = strings.ToLower(name)
		if !supportedClientHint(name) {
			return fmt.Errorf("browser: unsupported client-hint permission %q", name)
		}
		if seen[name] {
			return fmt.Errorf("browser: duplicate client-hint permission %q", name)
		}
		seen[name] = true
		for _, origin := range origins {
			if origin == "*" || origin == "self" {
				continue
			}
			parsed, err := url.Parse(origin)
			if err != nil || headerOrigin(parsed) == "" {
				return errors.New("browser: client-hint permission requires an HTTP or HTTPS origin")
			}
		}
	}

	return nil
}
