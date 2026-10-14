package http2

import (
	"slices"

	"github.com/aarock1234/fphttp/v2/internal/fingerprint"
)

// This file is fphttp-only. It gives HEADERS frames the stream dependencies
// Chromium sends (Http2PriorityDependencies in net/spdy).

// streamDependencies tracks the open streams of one connection whose
// HEADERS frames carried the profile's priority, as Chromium's
// Http2PriorityDependencies does. Chromium keeps one list of open streams
// per priority, in creation order, and makes each new stream depend
// exclusively on the last stream of the closest non-empty list at its own
// priority or higher, or on stream 0 when every such list is empty.
//
// Chromium derives the HTTP/2 weight from the priority with a strictly
// decreasing function (Spdy3PriorityToHttp2Weight), so comparing weights
// compares priorities, and streams of equal weight share a list.
//
// The zero value has no open streams. It is guarded by ClientConn.mu.
type streamDependencies struct {
	// open lists the open streams in the order their HEADERS were written.
	open []dependencyStream
}

// dependencyStream is one open stream and the wire weight of its HEADERS
// priority.
type dependencyStream struct {
	id     uint32
	weight uint8
}

// parent returns the stream a new stream with the given wire weight depends
// on: among the open streams of equal or higher weight, the most recent one
// of the lowest such weight. It returns 0, the root, when there is none.
func (d *streamDependencies) parent(weight uint8) uint32 {
	var parent dependencyStream
	found := false

	for _, stream := range d.open {
		if stream.weight < weight {
			continue
		}

		// A later stream of the same weight replaces an earlier one,
		// because Chromium picks the last stream of the list.
		if !found || stream.weight <= parent.weight {
			parent = stream
			found = true
		}
	}

	return parent.id
}

// add records that a stream with the given wire weight is open.
func (d *streamDependencies) add(id uint32, weight uint8) {
	d.open = append(d.open, dependencyStream{
		id:     id,
		weight: weight,
	})
}

// remove forgets a closed stream. Streams that were never added are
// ignored.
func (d *streamDependencies) remove(id uint32) {
	d.open = slices.DeleteFunc(d.open, func(stream dependencyStream) bool {
		return stream.id == id
	})
}

// headerPriority returns the priority to send in the HEADERS frame of the
// request on stream streamID. priority is the request's resolved priority
// and fromProfile reports that it is the profile's rather than the caller's.
//
// On a connection whose profile uses Chromium's dependencies, an enabled
// profile priority is replaced by a copy that depends on the stream
// Chromium would choose, and the stream is recorded as open until
// forgetStreamID. Every other priority, including a caller's H2Priority, is
// returned unchanged and its stream is not recorded, because the caller
// chose its dependency.
//
// The caller holds cc.wmu, so HEADERS frames are recorded in the order they
// are written.
func (cc *ClientConn) headerPriority(streamID uint32, priority *fingerprint.Priority, fromProfile bool) *fingerprint.Priority {
	if cc.dependencies == nil || !fromProfile || priority == nil || !priority.Enabled {
		return priority
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()

	chained := *priority
	chained.StreamDep = cc.dependencies.parent(priority.Weight)
	cc.dependencies.add(streamID, priority.Weight)

	return &chained
}

// forgetDependency removes a closed stream from the connection's Chromium
// stream dependencies, if it uses them. The caller holds cc.mu.
func (cc *ClientConn) forgetDependency(streamID uint32) {
	if cc.dependencies == nil {
		return
	}

	cc.dependencies.remove(streamID)
}
