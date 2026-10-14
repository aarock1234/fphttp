package main

import (
	"strconv"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// sourceSetting is one HTTP/2 SETTINGS value derived from source.
type sourceSetting struct {
	id    fingerprint.SettingID
	value uint32
}

// differSettings appends a difference for every setting whose value in the
// catalog's HTTP/2 template differs from the source value, and one for the
// connection WINDOW_UPDATE increment.
func differSettings(
	diffs []difference,
	template fingerprint.HTTP2,
	settings []sourceSetting,
	connectionFlow uint32,
) []difference {
	for _, setting := range settings {
		diffs = differ(diffs, setting.id.String(), settingText(template, setting.id), formatUint(setting.value))
	}

	return differ(diffs, "connection window increment", template.ConnectionFlow, connectionFlow)
}

// settingText formats the value of one SETTINGS parameter of template, or
// "not sent".
func settingText(template fingerprint.HTTP2, id fingerprint.SettingID) string {
	value, ok := template.SettingValue(id)
	if !ok {
		return "not sent"
	}

	return formatUint(value)
}

// formatUint formats a SETTINGS value.
func formatUint(value uint32) string {
	return strconv.FormatUint(uint64(value), 10)
}
