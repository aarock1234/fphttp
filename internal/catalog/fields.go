package catalog

// Field is one header field name and value.
type Field struct {
	// Name is the canonical field name, such as "Te".
	Name string

	// Value is the field value.
	Value string
}

// HTTP2OnlyFields returns the fields the release appends after every other
// field on HTTP/2 requests and never sends on HTTP/1.1, in wire order, for a
// request destination (see Accept). Firefox sends te: trailers on every
// HTTP/2 request; other browsers send nothing extra. It returns nil for an
// unknown destination. The caller owns the returned slice.
func (e Entry) HTTP2OnlyFields(destination string) []Field {
	if e.Family != FamilyFirefox || parseDestination(destination) == destinationUnknown {
		return nil
	}

	return []Field{
		{
			Name:  "Te",
			Value: "trailers",
		},
	}
}

// RequestFields returns the fields the release adds to every request for a
// request destination (see Accept) on HTTP/1.1 and HTTP/2, beyond the
// content negotiation, fetch metadata, client hint, and priority fields
// other methods describe. It returns nil for an unknown destination or when
// the release adds nothing. The caller owns the returned slice.
//
// Brave sends Sec-GPC: 1 on every request, because its Global Privacy
// Control is on by default (brave-core
// browser/net/global_privacy_control_network_delegate_helper.cc). Chromium
// and Firefox mark a service worker's main script request with
// Service-Worker: script (Chromium service_worker_new_script_loader.cc,
// Firefox ServiceWorkerScriptCache.cpp).
func (e Entry) RequestFields(destination string) []Field {
	kind := parseDestination(destination)
	if kind == destinationUnknown {
		return nil
	}

	var fields []Field

	if e.Browser == Brave {
		fields = append(fields, Field{
			Name:  "Sec-Gpc",
			Value: "1",
		})
	}

	if kind == destinationServiceWorker && e.Family != FamilySafari {
		fields = append(fields, Field{
			Name:  "Service-Worker",
			Value: "script",
		})
	}

	return fields
}
