package catalog

// Header layouts per engine family. Orders list canonical field names in
// wire order. The Chromium and Firefox orders come from browser source and
// captures. The Safari orders follow their captures, then list uncaptured
// fields in lexical order, as fphttp v1 placed them.
//
// A field an order leaves out, such as Transfer-Encoding in the Firefox and
// Safari orders, follows the listed fields in the lexical order fphttp uses
// for unlisted fields. HTTP/2 drops the connection-specific fields (Host,
// Connection, Proxy-Connection, Transfer-Encoding) on the wire. Every slice
// and map here is shared by all wires of its family and must not be
// modified.

// Pseudo-header orders.
var (
	// chromiumPseudoHeaderOrder is :method, :authority, :scheme, :path.
	chromiumPseudoHeaderOrder = []string{
		":method",
		":authority",
		":scheme",
		":path",
	}

	// firefoxPseudoHeaderOrder is :method, :path, :authority, :scheme.
	firefoxPseudoHeaderOrder = []string{
		":method",
		":path",
		":authority",
		":scheme",
	}

	// safariPseudoHeaderOrder is :method, :scheme, :authority, :path.
	safariPseudoHeaderOrder = []string{
		":method",
		":scheme",
		":authority",
		":path",
	}
)

// chromiumNavigationOrder is the order Chromium assembles a frame
// navigation in, identical in structure on every platform from 108 to 155:
// the network prefix (Host, Connection, cache directives, authorization),
// client hints, Accept-Language, renderer fields, DNT and Sec-GPC,
// Upgrade-Insecure-Requests, User-Agent, Origin, Accept, fetch metadata,
// then the network tail. It matches the Chrome 148 Windows capture.
//
// Accept-Language sits early, as in the Chrome 148 and 154 captures; the
// compiled default without the ReduceAcceptLanguage field trial would
// append it after Accept-Encoding instead. Origin follows User-Agent because
// the browser process appends it for non-GET navigations (verified at 152+).
var chromiumNavigationOrder = []string{
	"Host",
	"Connection",
	"Proxy-Connection",
	"Content-Length",
	"Transfer-Encoding",
	"Pragma",
	"Cache-Control",
	"Proxy-Authorization",
	"Authorization",
	"Device-Memory",
	"Sec-Ch-Device-Memory",
	"Dpr",
	"Sec-Ch-Dpr",
	"Viewport-Width",
	"Sec-Ch-Viewport-Width",
	"Sec-Ch-Viewport-Height",
	"Rtt",
	"Downlink",
	"Ect",
	"Sec-Ch-Ua",
	"Sec-Ch-Ua-Mobile",
	"Sec-Ch-Ua-Full-Version",
	"Sec-Ch-Ua-Arch",
	"Sec-Ch-Ua-Platform",
	"Sec-Ch-Ua-Platform-Version",
	"Sec-Ch-Ua-Model",
	"Sec-Ch-Ua-Bitness",
	"Sec-Ch-Ua-Wow64",
	"Sec-Ch-Ua-Full-Version-List",
	"Sec-Ch-Ua-Form-Factors",
	"Sec-Ch-Prefers-Color-Scheme",
	"Sec-Ch-Prefers-Reduced-Motion",
	"Sec-Ch-Prefers-Reduced-Transparency",
	"Save-Data",
	"Accept-Language",
	"Content-Type",
	"Dnt",
	"Sec-Gpc",
	"Upgrade-Insecure-Requests",
	"User-Agent",
	"Origin",
	"Accept",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-User",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Storage-Access",
	"Referer",
	"Accept-Encoding",
	"Cookie",
	"If-None-Match",
	"If-Modified-Since",
	"Priority",
}

// chromiumSubresourceOrder is the order of a renderer subresource request:
// the network prefix, the renderer's fields in the order the Chrome 148
// Windows and 154 macOS fetch captures agree on, Accept, the CORS Origin,
// fetch metadata, then the network tail.
//
// Blink copies its renderer fields in hash order (rapidhash since Chromium
// 129), and Accept follows them. The captures show only part of that block.
// The renderer fields they do not show, Sec-Gpc through Save-Data below,
// deliberately extend the captured list: they sit at the end of the
// renderer block, ahead of Accept as in source, instead of after the whole
// list in the lexical order used for unlisted fields. Their order inside
// the block is not verified.
var chromiumSubresourceOrder = []string{
	"Host",
	"Connection",
	"Proxy-Connection",
	"Content-Length",
	"Transfer-Encoding",
	"Pragma",
	"Cache-Control",
	"Proxy-Authorization",
	"Authorization",
	"Sec-Ch-Ua-Platform",
	"Accept-Language",
	"Sec-Ch-Ua",
	"Dnt",
	"User-Agent",
	"Sec-Ch-Ua-Mobile",
	"Sec-Gpc",
	"Content-Type",
	"Range",
	"Sec-Ch-Ua-Full-Version",
	"Sec-Ch-Ua-Arch",
	"Sec-Ch-Ua-Platform-Version",
	"Sec-Ch-Ua-Model",
	"Sec-Ch-Ua-Bitness",
	"Sec-Ch-Ua-Wow64",
	"Sec-Ch-Ua-Full-Version-List",
	"Sec-Ch-Ua-Form-Factors",
	"Device-Memory",
	"Sec-Ch-Device-Memory",
	"Dpr",
	"Sec-Ch-Dpr",
	"Width",
	"Sec-Ch-Width",
	"Viewport-Width",
	"Sec-Ch-Viewport-Width",
	"Sec-Ch-Viewport-Height",
	"Rtt",
	"Downlink",
	"Ect",
	"Sec-Ch-Prefers-Color-Scheme",
	"Sec-Ch-Prefers-Reduced-Motion",
	"Sec-Ch-Prefers-Reduced-Transparency",
	"Save-Data",
	"Accept",
	"Origin",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Storage-Access",
	"Referer",
	"Accept-Encoding",
	"Cookie",
	"If-None-Match",
	"If-Modified-Since",
	"Priority",
}

// chromiumHeaderCase spells the fields Chromium does not write in canonical
// form on HTTP/1.1: client hints come from lowercase name tables, and DNT
// and Sec-GPC are upper-case constants.
//
// Save-Data is lowercase only on navigations; Blink subresources send
// "Save-Data". The navigation spelling is used because the zero request
// destination is a navigation.
var chromiumHeaderCase = map[string]string{
	"Device-Memory":                       "device-memory",
	"Dnt":                                 "DNT",
	"Downlink":                            "downlink",
	"Dpr":                                 "dpr",
	"Ect":                                 "ect",
	"Rtt":                                 "rtt",
	"Save-Data":                           "save-data",
	"Sec-Ch-Device-Memory":                "sec-ch-device-memory",
	"Sec-Ch-Dpr":                          "sec-ch-dpr",
	"Sec-Ch-Prefers-Color-Scheme":         "sec-ch-prefers-color-scheme",
	"Sec-Ch-Prefers-Reduced-Motion":       "sec-ch-prefers-reduced-motion",
	"Sec-Ch-Prefers-Reduced-Transparency": "sec-ch-prefers-reduced-transparency",
	"Sec-Ch-Ua":                           "sec-ch-ua",
	"Sec-Ch-Ua-Arch":                      "sec-ch-ua-arch",
	"Sec-Ch-Ua-Bitness":                   "sec-ch-ua-bitness",
	"Sec-Ch-Ua-Form-Factors":              "sec-ch-ua-form-factors",
	"Sec-Ch-Ua-Full-Version":              "sec-ch-ua-full-version",
	"Sec-Ch-Ua-Full-Version-List":         "sec-ch-ua-full-version-list",
	"Sec-Ch-Ua-Mobile":                    "sec-ch-ua-mobile",
	"Sec-Ch-Ua-Model":                     "sec-ch-ua-model",
	"Sec-Ch-Ua-Platform":                  "sec-ch-ua-platform",
	"Sec-Ch-Ua-Platform-Version":          "sec-ch-ua-platform-version",
	"Sec-Ch-Ua-Wow64":                     "sec-ch-ua-wow64",
	"Sec-Ch-Viewport-Height":              "sec-ch-viewport-height",
	"Sec-Ch-Viewport-Width":               "sec-ch-viewport-width",
	"Sec-Ch-Width":                        "sec-ch-width",
	"Sec-Gpc":                             "Sec-GPC",
	"Viewport-Width":                      "viewport-width",
	"Width":                               "width",
}

// firefoxNavigationOrder is Firefox's field insertion order for document
// and iframe loads, the same from 102 to 158 and on every ESR: Host and the
// standard fields, loader fields (Referer, upload fields), BeginConnect
// fields (storage access from 147, Origin, DNT, Sec-GPC, authorization,
// Connection), Cookie, Upgrade-Insecure-Requests and fetch metadata, cache
// validators, Priority (from 126), cache directives, and Te, which Firefox
// appends last on HTTP/2 only.
//
// The positions of Content-Type and Content-Length on form-POST navigations
// and of Proxy-Authorization are not verified; they follow the subresource
// upload and authorization positions.
var firefoxNavigationOrder = []string{
	"Host",
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Content-Type",
	"Referer",
	"Content-Length",
	"Sec-Fetch-Storage-Access",
	"Origin",
	"Dnt",
	"Sec-Gpc",
	"Proxy-Authorization",
	"Authorization",
	"Connection",
	"Cookie",
	"Upgrade-Insecure-Requests",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Sec-Fetch-User",
	"If-Modified-Since",
	"If-None-Match",
	"Priority",
	"Pragma",
	"Cache-Control",
	"Te",
}

// firefoxSubresourceOrder is Firefox's field insertion order for fetch,
// XHR, and subresource loads. Caller fields such as Content-Type and a media
// Range sit between Accept-Encoding and Referer; the upload stream then adds
// Content-Length. Subresources never carry Upgrade-Insecure-Requests or
// Sec-Fetch-User. The Range and Proxy-Authorization positions are not
// verified.
var firefoxSubresourceOrder = []string{
	"Host",
	"User-Agent",
	"Accept",
	"Accept-Language",
	"Accept-Encoding",
	"Content-Type",
	"Range",
	"Referer",
	"Content-Length",
	"Sec-Fetch-Storage-Access",
	"Origin",
	"Dnt",
	"Sec-Gpc",
	"Proxy-Authorization",
	"Authorization",
	"Connection",
	"Cookie",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"If-Modified-Since",
	"If-None-Match",
	"Priority",
	"Pragma",
	"Cache-Control",
	"Te",
}

// firefoxHeaderCase spells the fields Firefox does not write in canonical
// form on HTTP/1.1, from its header atom table. TE is listed for
// completeness; Firefox sends it on HTTP/2 only.
var firefoxHeaderCase = map[string]string{
	"Dnt":     "DNT",
	"Sec-Gpc": "Sec-GPC",
	"Te":      "TE",
}

// safariNavigationOrder is the captured Safari 26 and 27 navigation order on
// macOS and iPhone. Safari sends neither Upgrade-Insecure-Requests nor
// Sec-Fetch-User on these navigations, so the order omits both, and
// Entry.UpgradeInsecureRequests and Entry.SecFetchUser return "" for Safari.
//
// Fields after Accept-Encoding are not captured; they keep fphttp v1's
// placement of unlisted fields, in lexical order after the captured ones.
var safariNavigationOrder = []string{
	"Host",
	"Connection",
	"Sec-Fetch-Dest",
	"User-Agent",
	"Accept",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"Accept-Language",
	"Priority",
	"Accept-Encoding",
	"Authorization",
	"Cache-Control",
	"Content-Length",
	"Content-Type",
	"Cookie",
	"If-Modified-Since",
	"If-None-Match",
	"Origin",
	"Pragma",
	"Proxy-Authorization",
	"Referer",
}

// safariMacSubresourceOrder is the captured Safari 27 macOS fetch order,
// where Pragma precedes Sec-Fetch-Site. Safari 26.0 shares it without a
// fetch capture of its own. Fields after Accept-Encoding are not captured
// and keep fphttp v1's lexical placement.
var safariMacSubresourceOrder = []string{
	"Host",
	"Connection",
	"Accept",
	"Pragma",
	"Sec-Fetch-Site",
	"Sec-Fetch-Mode",
	"User-Agent",
	"Sec-Fetch-Dest",
	"Cache-Control",
	"Accept-Language",
	"Priority",
	"Accept-Encoding",
	"Authorization",
	"Content-Length",
	"Content-Type",
	"Cookie",
	"If-Modified-Since",
	"If-None-Match",
	"Origin",
	"Proxy-Authorization",
	"Range",
	"Referer",
}

// safariIOSSubresourceOrder is the captured Safari 27 iPhone fetch order,
// where Sec-Fetch-Site precedes Pragma. Fields after Accept-Encoding are not
// captured and keep fphttp v1's lexical placement.
var safariIOSSubresourceOrder = []string{
	"Host",
	"Connection",
	"Accept",
	"Sec-Fetch-Site",
	"Pragma",
	"Sec-Fetch-Mode",
	"User-Agent",
	"Sec-Fetch-Dest",
	"Cache-Control",
	"Accept-Language",
	"Priority",
	"Accept-Encoding",
	"Authorization",
	"Content-Length",
	"Content-Type",
	"Cookie",
	"If-Modified-Since",
	"If-None-Match",
	"Origin",
	"Proxy-Authorization",
	"Range",
	"Referer",
}
