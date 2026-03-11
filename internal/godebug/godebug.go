// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package godebug is a lightweight replacement for the standard library's
// internal/godebug. It reads settings from the $GODEBUG environment
// variable without depending on runtime-internal hooks that are
// unavailable outside the standard library.
package godebug

import (
	"os"
	"sync"
)

// A Setting is a single setting in the $GODEBUG environment variable.
type Setting struct {
	name string
	once sync.Once
	val  string
}

// New returns a new Setting for the $GODEBUG setting with the given name.
func New(name string) *Setting {
	return &Setting{name: name}
}

// Name returns the name of the setting.
func (s *Setting) Name() string {
	if s.name != "" && s.name[0] == '#' {
		return s.name[1:]
	}

	return s.name
}

// Undocumented reports whether this is an undocumented setting.
func (s *Setting) Undocumented() bool {
	return s.name != "" && s.name[0] == '#'
}

// String returns a printable form for the setting: name=value.
func (s *Setting) String() string {
	return s.Name() + "=" + s.Value()
}

// Value returns the current value for the GODEBUG setting s.
func (s *Setting) Value() string {
	s.once.Do(func() {
		s.val = lookup(s.Name())
	})

	return s.val
}

// IncNonDefault is a no-op in this fork. In the standard library it
// increments a runtime/metrics counter, but that mechanism relies on
// runtime-internal hooks unavailable outside the standard library.
func (s *Setting) IncNonDefault() {}

// lookup parses the GODEBUG environment variable for the given key.
func lookup(key string) string {
	env := os.Getenv("GODEBUG")
	for len(env) > 0 {
		// Find the next key=value pair.
		var pair string
		if i := indexOf(env, ','); i >= 0 {
			pair, env = env[:i], env[i+1:]
		} else {
			pair, env = env, ""
		}

		if eq := indexOf(pair, '='); eq >= 0 {
			if pair[:eq] == key {
				return pair[eq+1:]
			}
		}
	}

	return ""
}

// indexOf returns the index of the first occurrence of b in s, or -1.
func indexOf(s string, b byte) int {
	for i := range len(s) {
		if s[i] == b {
			return i
		}
	}

	return -1
}
