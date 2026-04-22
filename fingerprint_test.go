package http

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestFingerprint_Clone(t *testing.T) {
	t.Run("nil receiver returns nil", func(t *testing.T) {
		var f *Fingerprint
		got := f.Clone()
		if got != nil {
			t.Fatalf("Clone() = %v, want nil", got)
		}
	})

	t.Run("scalar fields are copied", func(t *testing.T) {
		f := &Fingerprint{
			ClientHelloID: utls.HelloChrome_Auto,
			H2: H2Fingerprint{
				ConnectionFlow: 15663105,
				HeaderPriority: H2Priority{
					Enabled:   true,
					StreamDep: 13,
					Exclusive: true,
					Weight:    41,
				},
			},
		}

		clone := f.Clone()

		if clone.ClientHelloID != f.ClientHelloID {
			t.Errorf("ClientHelloID = %v, want %v", clone.ClientHelloID, f.ClientHelloID)
		}
		if clone.H2.ConnectionFlow != f.H2.ConnectionFlow {
			t.Errorf("H2.ConnectionFlow = %d, want %d", clone.H2.ConnectionFlow, f.H2.ConnectionFlow)
		}
		if clone.H2.HeaderPriority != f.H2.HeaderPriority {
			t.Errorf("H2.HeaderPriority = %+v, want %+v", clone.H2.HeaderPriority, f.H2.HeaderPriority)
		}
	})

	t.Run("ClientHelloSpec pointer is shared not deep-copied", func(t *testing.T) {
		spec := &utls.ClientHelloSpec{
			TLSVersMin: utls.VersionTLS12,
			TLSVersMax: utls.VersionTLS13,
		}
		f := &Fingerprint{
			ClientHelloSpec: spec,
		}

		clone := f.Clone()
		if clone.ClientHelloSpec != f.ClientHelloSpec {
			t.Errorf("ClientHelloSpec pointer = %p, want shared %p", clone.ClientHelloSpec, f.ClientHelloSpec)
		}
	})

	t.Run("mutating HeaderOrder does not affect original", func(t *testing.T) {
		f := &Fingerprint{
			HeaderOrder: []string{"Host", "Accept", "User-Agent"},
		}
		original := slices.Clone(f.HeaderOrder)

		clone := f.Clone()
		clone.HeaderOrder[0] = "X-Mutated"

		if !slices.Equal(f.HeaderOrder, original) {
			t.Errorf("original HeaderOrder was mutated: got %v, want %v", f.HeaderOrder, original)
		}
	})

	t.Run("mutating PseudoHeaderOrder does not affect original", func(t *testing.T) {
		f := &Fingerprint{
			PseudoHeaderOrder: []string{":method", ":path", ":authority", ":scheme"},
		}
		original := slices.Clone(f.PseudoHeaderOrder)

		clone := f.Clone()
		clone.PseudoHeaderOrder[0] = ":mutated"

		if !slices.Equal(f.PseudoHeaderOrder, original) {
			t.Errorf("original PseudoHeaderOrder was mutated: got %v, want %v", f.PseudoHeaderOrder, original)
		}
	})

	t.Run("mutating H2.Settings does not affect original", func(t *testing.T) {
		f := &Fingerprint{
			H2: H2Fingerprint{
				Settings: []H2Setting{
					{ID: H2SettingHeaderTableSize, Val: 65536},
					{ID: H2SettingEnablePush, Val: 0},
				},
			},
		}
		origVal := f.H2.Settings[0].Val

		clone := f.Clone()
		clone.H2.Settings[0].Val = 99999

		if f.H2.Settings[0].Val != origVal {
			t.Errorf("original H2.Settings[0].Val = %d, want %d", f.H2.Settings[0].Val, origVal)
		}
	})

	t.Run("mutating H2.InitPriorityFrames does not affect original", func(t *testing.T) {
		f := &Fingerprint{
			H2: H2Fingerprint{
				InitPriorityFrames: []H2PriorityFrame{
					{StreamID: 3, StreamDep: 0, Weight: 200},
					{StreamID: 5, StreamDep: 0, Weight: 100},
				},
			},
		}
		origStreamID := f.H2.InitPriorityFrames[0].StreamID

		clone := f.Clone()
		clone.H2.InitPriorityFrames[0].StreamID = 999

		if f.H2.InitPriorityFrames[0].StreamID != origStreamID {
			t.Errorf("original InitPriorityFrames[0].StreamID = %d, want %d",
				f.H2.InitPriorityFrames[0].StreamID, origStreamID)
		}
	})
}

func TestFingerprint_Validate(t *testing.T) {
	tests := []struct {
		name    string
		fp      *Fingerprint
		wantErr string
	}{
		{
			name:    "nil fingerprint is valid",
			fp:      nil,
			wantErr: "",
		},
		{
			name:    "Chrome is valid",
			fp:      Chrome(),
			wantErr: "",
		},
		{
			name:    "Firefox is valid",
			fp:      Firefox(),
			wantErr: "",
		},
		{
			name:    "Safari is valid",
			fp:      Safari(),
			wantErr: "",
		},
		{
			name:    "SafariIOS is valid",
			fp:      SafariIOS(),
			wantErr: "",
		},
		{
			name:    "Edge is valid",
			fp:      Edge(),
			wantErr: "",
		},
		{
			name:    "Brave is valid",
			fp:      Brave(),
			wantErr: "",
		},
		{
			name:    "ChromeAndroid is valid",
			fp:      ChromeAndroid(),
			wantErr: "",
		},
		{
			name: "PseudoHeaderOrder wrong count",
			fp: &Fingerprint{
				PseudoHeaderOrder: []string{":method", ":path"},
			},
			wantErr: "missing required pseudo-header",
		},
		{
			name: "PseudoHeaderOrder unknown entry",
			fp: &Fingerprint{
				PseudoHeaderOrder: []string{":method", ":path", ":authority", ":bogus"},
			},
			wantErr: `contains invalid pseudo-header ":bogus"`,
		},
		{
			name: "PseudoHeaderOrder with duplicate entries",
			fp: &Fingerprint{
				PseudoHeaderOrder: []string{":method", ":method", ":path", ":authority"},
			},
			wantErr: `contains duplicate ":method"`,
		},
		{
			name: "duplicate H2 setting IDs",
			fp: &Fingerprint{
				H2: H2Fingerprint{
					Settings: []H2Setting{
						{ID: H2SettingHeaderTableSize, Val: 65536},
						{ID: H2SettingHeaderTableSize, Val: 4096},
					},
				},
			},
			wantErr: "duplicate H2 setting ID",
		},
		{
			name: "InitPriorityFrames with StreamID 0",
			fp: &Fingerprint{
				H2: H2Fingerprint{
					InitPriorityFrames: []H2PriorityFrame{
						{StreamID: 3, StreamDep: 0, Weight: 200},
						{StreamID: 0, StreamDep: 0, Weight: 100},
					},
				},
			},
			wantErr: "InitPriorityFrames[1] has StreamID 0",
		},
		{
			name: "HeaderOrder with non-canonical key",
			fp: &Fingerprint{
				HeaderOrder: []string{"content-type", "Accept"},
			},
			wantErr: `HeaderOrder key "content-type" is not canonical`,
		},
		{
			name:    "empty fingerprint is valid",
			fp:      &Fingerprint{},
			wantErr: "",
		},
		{
			name: "valid fingerprint with all fields set",
			fp: &Fingerprint{
				ClientHelloID: utls.HelloChrome_Auto,
				HeaderOrder:   []string{"Host", "Accept", "User-Agent"},
				PseudoHeaderOrder: []string{
					":method",
					":authority",
					":scheme",
					":path",
				},
				H2: H2Fingerprint{
					Settings: []H2Setting{
						{ID: H2SettingHeaderTableSize, Val: 65536},
						{ID: H2SettingEnablePush, Val: 0},
						{ID: H2SettingInitialWindowSize, Val: 6291456},
					},
					ConnectionFlow: 15663105,
					InitPriorityFrames: []H2PriorityFrame{
						{StreamID: 3, StreamDep: 0, Weight: 200},
						{StreamID: 5, StreamDep: 0, Weight: 100},
					},
					HeaderPriority: H2Priority{
						Enabled: true,
						Weight:  255,
					},
				},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fp.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}

				return
			}

			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestFingerprint_Validate_ReportsAllErrors(t *testing.T) {
	fp := &Fingerprint{
		PseudoHeaderOrder: []string{":method", ":path"},
		HeaderOrder:       []string{"content-type"},
		H2: H2Fingerprint{
			Settings: []H2Setting{
				{ID: H2SettingHeaderTableSize, Val: 65536},
				{ID: H2SettingHeaderTableSize, Val: 4096},
			},
			InitPriorityFrames: []H2PriorityFrame{
				{StreamID: 0, Weight: 100},
			},
		},
	}

	err := fp.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want aggregated error")
	}

	want := []string{
		"missing required pseudo-header",
		"duplicate H2 setting ID",
		"InitPriorityFrames[0] has StreamID 0",
		`HeaderOrder key "content-type" is not canonical`,
	}

	msg := err.Error()
	for _, w := range want {
		if !strings.Contains(msg, w) {
			t.Errorf("Validate() error missing substring %q\nfull error: %s", w, msg)
		}
	}
}

func TestH2SettingID_String(t *testing.T) {
	tests := []struct {
		id   H2SettingID
		want string
	}{
		{H2SettingHeaderTableSize, "HEADER_TABLE_SIZE"},
		{H2SettingEnablePush, "ENABLE_PUSH"},
		{H2SettingMaxConcurrentStreams, "MAX_CONCURRENT_STREAMS"},
		{H2SettingInitialWindowSize, "INITIAL_WINDOW_SIZE"},
		{H2SettingMaxFrameSize, "MAX_FRAME_SIZE"},
		{H2SettingMaxHeaderListSize, "MAX_HEADER_LIST_SIZE"},
		{H2SettingEnableConnectProtocol, "ENABLE_CONNECT_PROTOCOL"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.id.String(); got != tt.want {
				t.Errorf("H2SettingID(%d).String() = %q, want %q", tt.id, got, tt.want)
			}
		})
	}

	t.Run("unknown ID", func(t *testing.T) {
		id := H2SettingID(0xff)
		want := fmt.Sprintf("UNKNOWN(0x%x)", uint16(id))
		if got := id.String(); got != want {
			t.Errorf("H2SettingID(%d).String() = %q, want %q", id, got, want)
		}
	})
}

func TestProfile(t *testing.T) {
	tests := []struct {
		browser  Browser
		platform Platform
		wantHID  utls.ClientHelloID
		wantNil  bool
	}{
		{BrowserChrome, PlatformWindows, utls.HelloChrome_Auto, false},
		{BrowserChrome, PlatformMac, utls.HelloChrome_Auto, false},
		{BrowserChrome, PlatformLinux, utls.HelloChrome_Auto, false},
		{BrowserChrome, PlatformAndroid, utls.HelloChrome_Auto, false},
		{BrowserChrome, PlatformIOS, utls.HelloIOS_Auto, false},
		{BrowserChrome, PlatformIPadOS, utls.HelloIOS_Auto, false},
		{BrowserFirefox, PlatformWindows, utls.HelloFirefox_Auto, false},
		{BrowserFirefox, PlatformIOS, utls.HelloIOS_Auto, false},
		{BrowserSafari, PlatformMac, utls.HelloSafari_Auto, false},
		{BrowserSafari, PlatformIOS, utls.HelloIOS_Auto, false},
		{BrowserEdge, PlatformWindows, utls.HelloEdge_Auto, false},
		{BrowserBrave, PlatformWindows, utls.HelloChrome_Auto, false},
		{Browser("unknown"), PlatformWindows, utls.ClientHelloID{}, true},
	}

	for _, tt := range tests {
		name := fmt.Sprintf("%s_%s", tt.browser, tt.platform)
		t.Run(name, func(t *testing.T) {
			got := Profile(tt.browser, tt.platform)

			if tt.wantNil {
				if got != nil {
					t.Errorf("Profile(%v, %v) = %v, want nil", tt.browser, tt.platform, got)
				}

				return
			}

			if got == nil {
				t.Fatalf("Profile(%v, %v) = nil, want non-nil", tt.browser, tt.platform)
			}
			if got.ClientHelloID != tt.wantHID {
				t.Errorf("ClientHelloID = %v, want %v", got.ClientHelloID, tt.wantHID)
			}
			if err := got.Validate(); err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}
