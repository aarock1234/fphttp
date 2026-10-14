package browser

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	http "github.com/aarock1234/fphttp/v2"
)

func configureSettingsGREASE(fingerprint *http.Fingerprint) {
	settings := slices.Clone(fingerprint.H2.Settings)
	fingerprint.H2.Settings = nil
	fingerprint.H2.SettingsFactory = func() ([]http.H2Setting, error) {
		var entropy [6]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return nil, fmt.Errorf("generate H2 SETTINGS GREASE: %w", err)
		}
		id := uint16(0x0a0a) + uint16(entropy[0]&0x0f)*0x1000 + uint16(entropy[1]&0x0f)*0x0010
		result := slices.Clone(settings)
		result = append(result, http.H2Setting{
			ID:  http.H2SettingID(id),
			Val: binary.BigEndian.Uint32(entropy[2:]),
		})

		return result, nil
	}
}
