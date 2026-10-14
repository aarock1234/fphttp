package http

import (
	"slices"
	"sync"
)

// clientHintStore remembers, per origin, the client hints that the origin
// asked for with Accept-CH. Each Transport with a profile has its own store,
// which Transport.Clone never shares. It is safe for concurrent use, and
// the zero value is an empty store ready to use.
type clientHintStore struct {
	mu sync.Mutex

	// accepted maps an origin, serialized by requestOrigin, to the
	// lowercase names of the hints it asked for. Its slices are replaced,
	// never modified, so readers may keep them.
	accepted map[string][]string
}

// hints returns the lowercase names of the client hints origin asked for,
// or nil when it asked for none. The result is shared and must not be
// modified.
func (s *clientHintStore) hints(origin string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.accepted[origin]
}

// remember records that origin asked for hints, replacing what it asked
// for before. An empty hints list forgets the origin, as an empty valid
// Accept-CH field does. hints is copied.
func (s *clientHintStore) remember(origin string, hints []string) {
	if len(hints) == 0 {
		s.forget(origin)

		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.accepted == nil {
		s.accepted = make(map[string][]string)
	}

	s.accepted[origin] = slices.Clone(hints)
}

// forget removes everything origin asked for, as Clear-Site-Data does.
func (s *clientHintStore) forget(origin string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.accepted, origin)
}
