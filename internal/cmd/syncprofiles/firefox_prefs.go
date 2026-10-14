package main

import (
	"fmt"
	"strconv"
	"strings"

	http "github.com/aarock1234/fphttp"
)

// firefoxPreference recognizes only stable-build branches used by the modeled
// preferences. A new conditional form requires review before it becomes usable.
func firefoxPreference(source, name string, platform http.Platform, absent string) (string, error) {
	start := strings.Index(source, "name: "+name+"\n")
	if start < 0 {
		if absent != "" {
			return absent, nil
		}

		return "", fmt.Errorf("missing Firefox preference %s", name)
	}
	block := source[start:]
	if end := strings.Index(block[6:], "\n- name:"); end >= 0 {
		block = block[:end+6]
	}

	active := true
	conditional := false
	selected := ""
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "#if"):
			if conditional {
				return "", fmt.Errorf("nested conditional for Firefox preference %s", name)
			}
			var err error
			active, err = firefoxPreferenceBranch(line, platform)
			if err != nil {
				return "", fmt.Errorf("Firefox preference %s: %w", name, err)
			}
			conditional = true
		case line == "#else":
			if conditional {
				active = !active
			}
		case line == "#endif":
			active = true
			conditional = false
		case strings.HasPrefix(line, "#elif"):
			return "", fmt.Errorf("unsupported conditional for Firefox preference %s", name)
		case active && strings.HasPrefix(line, "value:"):
			fields := strings.Fields(strings.TrimPrefix(line, "value:"))
			if len(fields) == 0 || selected != "" {
				return "", fmt.Errorf("ambiguous Firefox preference %s", name)
			}
			value, err := firefoxPreferenceValue(fields[0], platform)
			if err != nil {
				return "", fmt.Errorf("Firefox preference %s: %w", name, err)
			}
			selected = value
		}
	}
	if selected == "" {
		return "", fmt.Errorf("missing active value for Firefox preference %s", name)
	}

	return selected, nil
}

func firefoxPreferenceBranch(directive string, platform http.Platform) (bool, error) {
	compact := strings.Join(strings.Fields(directive), "")
	switch compact {
	case "#ifdefANDROID", "#ifdefined(ANDROID)", "#ifdefined(ANDROID)&&!defined(EARLY_BETA_OR_EARLIER)":
		return platform == http.PlatformAndroid, nil
	case "#ifndefANDROID", "#if!defined(ANDROID)":
		return platform != http.PlatformAndroid, nil
	case "#ifdefNIGHTLY_BUILD", "#ifdefEARLY_BETA_OR_EARLIER", "#ifdefined(NIGHTLY_BUILD)", "#ifdefined(EARLY_BETA_OR_EARLIER)":
		return false, nil
	default:
		return false, fmt.Errorf("unrecognized branch %q", directive)
	}
}

func firefoxPreferenceValue(value string, platform http.Platform) (string, error) {
	switch value {
	case "true", "false":
		return value, nil
	case "@IS_ANDROID@":
		return strconv.FormatBool(platform == http.PlatformAndroid), nil
	case "@IS_NOT_ANDROID@":
		return strconv.FormatBool(platform != http.PlatformAndroid), nil
	case "@IS_NIGHTLY_BUILD@", "@IS_EARLY_BETA_OR_EARLIER@":
		return "false", nil
	case "@IS_NOT_NIGHTLY_BUILD@", "@IS_NOT_EARLY_BETA_OR_EARLIER@":
		return "true", nil
	default:
		if _, err := strconv.ParseUint(value, 10, 32); err != nil {
			return "", fmt.Errorf("unrecognized value %q", value)
		}

		return value, nil
	}
}
