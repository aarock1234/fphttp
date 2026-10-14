//go:build integration

package http_test

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	http "github.com/aarock1234/fphttp/v2"
)

type peetResponse struct {
	TLS struct {
		JA3Hash       string `json:"ja3_hash"`
		JA4           string `json:"ja4"`
		PeetPrintHash string `json:"peetprint_hash"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiHash string `json:"akamai_fingerprint_hash"`
		SentFrames []struct {
			FrameType string `json:"frame_type"`
		} `json:"sent_frames"`
	} `json:"http2"`
}

func TestIntegration_ChromeFingerprint(t *testing.T) {
	profile, err := http.NewProfile(http.BrowserChrome, http.PlatformWindows, http.Latest)
	if err != nil {
		t.Fatalf("NewProfile() error: %v", err)
	}

	client := http.NewClient(profile)

	req, err := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	var pr peetResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	t.Logf("ja3_hash:                  %s", pr.TLS.JA3Hash)
	t.Logf("ja4:                       %s", pr.TLS.JA4)
	t.Logf("peetprint_hash:            %s", pr.TLS.PeetPrintHash)
	t.Logf("akamai_fingerprint_hash:   %s", pr.HTTP2.AkamaiHash)

	if pr.TLS.JA3Hash == "" {
		t.Errorf("tls.ja3_hash is empty")
	}
	if pr.TLS.JA4 == "" {
		t.Errorf("tls.ja4 is empty")
	}
	if pr.HTTP2.AkamaiHash == "" {
		t.Errorf("http2.akamai_fingerprint_hash is empty")
	}

	var hasSettings, hasWindowUpdate bool
	for _, f := range pr.HTTP2.SentFrames {
		switch f.FrameType {
		case "SETTINGS":
			hasSettings = true
		case "WINDOW_UPDATE":
			hasWindowUpdate = true
		}
	}

	if !hasSettings {
		t.Errorf("expected SETTINGS frame in sent_frames")
	}
	if !hasWindowUpdate {
		t.Errorf("expected WINDOW_UPDATE frame in sent_frames")
	}
}

func TestIntegration_FirefoxFingerprint(t *testing.T) {
	// Firefox 120 still sends the legacy HTTP/2 priority tree.
	profile, err := http.NewProfile(http.BrowserFirefox, http.PlatformWindows, "120")
	if err != nil {
		t.Fatalf("NewProfile() error: %v", err)
	}

	client := http.NewClient(profile)

	req, err := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	var pr peetResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	t.Logf("ja3_hash:                  %s", pr.TLS.JA3Hash)
	t.Logf("ja4:                       %s", pr.TLS.JA4)
	t.Logf("peetprint_hash:            %s", pr.TLS.PeetPrintHash)
	t.Logf("akamai_fingerprint_hash:   %s", pr.HTTP2.AkamaiHash)

	if pr.TLS.JA3Hash == "" {
		t.Errorf("tls.ja3_hash is empty")
	}
	if pr.TLS.JA4 == "" {
		t.Errorf("tls.ja4 is empty")
	}
	if pr.HTTP2.AkamaiHash == "" {
		t.Errorf("http2.akamai_fingerprint_hash is empty")
	}

	var hasSettings, hasWindowUpdate, hasPriority bool
	for _, f := range pr.HTTP2.SentFrames {
		switch f.FrameType {
		case "SETTINGS":
			hasSettings = true
		case "WINDOW_UPDATE":
			hasWindowUpdate = true
		case "PRIORITY":
			hasPriority = true
		}
	}

	if !hasSettings {
		t.Errorf("expected SETTINGS frame in sent_frames")
	}
	if !hasWindowUpdate {
		t.Errorf("expected WINDOW_UPDATE frame in sent_frames")
	}
	if !hasPriority {
		t.Errorf("expected PRIORITY frame in sent_frames (Firefox 120 sends the legacy priority tree)")
	}
}

func TestIntegration_NilFingerprint(t *testing.T) {
	client := &http.Client{
		Transport: &http.Transport{},
	}

	req, err := http.NewRequest("GET", "https://tls.peet.ws/api/all", nil)
	if err != nil {
		t.Fatalf("NewRequest() error: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	var pr peetResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}

	t.Logf("ja3_hash:                  %s", pr.TLS.JA3Hash)
	t.Logf("ja4:                       %s", pr.TLS.JA4)
	t.Logf("peetprint_hash:            %s", pr.TLS.PeetPrintHash)
	t.Logf("akamai_fingerprint_hash:   %s", pr.HTTP2.AkamaiHash)

	if pr.TLS.JA3Hash == "" {
		t.Errorf("tls.ja3_hash is empty")
	}
	if pr.TLS.JA4 == "" {
		t.Errorf("tls.ja4 is empty")
	}

	// Verify the response body was valid JSON with actual content.
	if !strings.Contains(string(body), "ja3_hash") {
		t.Errorf("response body does not contain expected fingerprint data")
	}
}

// TestIntegration_HPACKDynamicTableGrowth exercises the HPACK decoder against
// a server (Cloudflare's edge fronting cloudflare.com) that emits dynamic
// table size updates above the 4096-byte default. Before the decoder size
// was sourced from Profile.HTTP2.Settings, the Chrome profile would announce
// SETTINGS_HEADER_TABLE_SIZE=65536 while the local decoder remained capped
// at 4096, so the first oversized update would terminate the connection
// with COMPRESSION_ERROR. This test fails the same way without that fix.
func TestIntegration_HPACKDynamicTableGrowth(t *testing.T) {
	tests := []struct {
		name     string
		browser  http.Browser
		platform http.Platform
	}{
		{"chrome", http.BrowserChrome, http.PlatformWindows},
		{"firefox", http.BrowserFirefox, http.PlatformWindows},
		{"safari", http.BrowserSafari, http.PlatformMac},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := http.NewProfile(tt.browser, tt.platform, http.Latest)
			if err != nil {
				t.Fatalf("NewProfile() error: %v", err)
			}

			client := http.NewClient(profile)

			req, err := http.NewRequest("GET", "https://www.cloudflare.com/", nil)
			if err != nil {
				t.Fatalf("NewRequest() error: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				if strings.Contains(err.Error(), "COMPRESSION_ERROR") {
					t.Fatalf("HPACK decoder rejected dynamic table size update: %v", err)
				}
				t.Fatalf("Do() error: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()

			n, err := io.Copy(io.Discard, resp.Body)
			if err != nil {
				if strings.Contains(err.Error(), "COMPRESSION_ERROR") {
					t.Fatalf("HPACK decoder rejected mid-stream: %v", err)
				}
				if !errors.Is(err, io.EOF) {
					t.Fatalf("reading body: %v", err)
				}
			}

			if n == 0 {
				t.Errorf("expected non-empty response body, got 0 bytes")
			}
			if resp.StatusCode != 200 {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
		})
	}
}
