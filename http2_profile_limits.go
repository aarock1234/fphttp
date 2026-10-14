//go:build !nethttpomithttp2 && !nethttpomithttp2client

package http

import (
	"fmt"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
	"github.com/aarock1234/fphttp/v2/internal/http2"
)

// validateProfileHTTP2Limits rejects Profile.HTTP2 settings that the HTTP/2
// transport would honor less than it advertises because of the Transport's
// own limits.
//
// The only such setting is MAX_HEADER_LIST_SIZE: a connection enforces the
// smaller of the advertised value and the response header limit the
// Transport derives from MaxResponseHeaderBytes (10 MiB by default), so a
// larger advertised value would promise servers headers the Transport then
// rejects. Every other SETTINGS value and ConnectionFlow is sent and
// enforced exactly as given once fingerprint.HTTP2.Validate accepts it.
func (t *Transport) validateProfileHTTP2Limits(snapshot *Profile) error {
	advertised, present := snapshot.HTTP2.SettingValue(fingerprint.SettingMaxHeaderListSize)
	if !present {
		return nil
	}

	limit := http2.ResponseHeaderListLimit(transportConfig{t})
	if limit == 0 || advertised <= limit {
		return nil
	}

	return fmt.Errorf(
		"fphttp: Profile.HTTP2 MAX_HEADER_LIST_SIZE %d exceeds the Transport's response header list limit of %d; lower it or raise Transport.MaxResponseHeaderBytes",
		advertised,
		limit,
	)
}
