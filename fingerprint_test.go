package http

import (
	"fmt"
	"testing"
)

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

func TestH2Fingerprint_SettingValue(t *testing.T) {
	h := HTTP2Profile{
		Settings: []H2Setting{
			{ID: H2SettingHeaderTableSize, Val: 65536},
			{ID: H2SettingEnablePush, Val: 0},
			{ID: H2SettingMaxHeaderListSize, Val: 262144},
		},
	}

	tests := []struct {
		name    string
		id      H2SettingID
		wantVal uint32
		wantOK  bool
	}{
		{"present_first", H2SettingHeaderTableSize, 65536, true},
		{"present_middle", H2SettingEnablePush, 0, true},
		{"present_last", H2SettingMaxHeaderListSize, 262144, true},
		{"absent", H2SettingMaxFrameSize, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := h.SettingValue(tt.id)
			if got != tt.wantVal || ok != tt.wantOK {
				t.Errorf("SettingValue(%v) = (%d, %v), want (%d, %v)", tt.id, got, ok, tt.wantVal, tt.wantOK)
			}
		})
	}

	t.Run("empty_settings", func(t *testing.T) {
		var h HTTP2Profile

		got, ok := h.SettingValue(H2SettingHeaderTableSize)
		if got != 0 || ok {
			t.Errorf("SettingValue() on zero value = (%d, %v), want (0, false)", got, ok)
		}
	})
}
