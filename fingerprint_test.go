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

	t.Run("mutating HeaderOrder does not affect original", func(t *testing.T) {
		f := &Fingerprint{
			HeaderOrder: []string{"Host", "Accept", "User-Agent"},
		}
		original := make([]string, len(f.HeaderOrder))
		copy(original, f.HeaderOrder)

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
		original := make([]string, len(f.PseudoHeaderOrder))
		copy(original, f.PseudoHeaderOrder)

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
			name: "PseudoHeaderOrder wrong count",
			fp: &Fingerprint{
				PseudoHeaderOrder: []string{":method", ":path"},
			},
			wantErr: "has 2 entries, want 4",
		},
		{
			name: "PseudoHeaderOrder missing required header",
			fp: &Fingerprint{
				PseudoHeaderOrder: []string{":method", ":path", ":authority", ":bogus"},
			},
			wantErr: "must contain exactly",
		},
		{
			name: "PseudoHeaderOrder with duplicate entries",
			fp: &Fingerprint{
				PseudoHeaderOrder: []string{":method", ":method", ":path", ":authority"},
			},
			wantErr: "must contain exactly",
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
						Weight: 255,
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
