package main

import (
	"context"
	"sync"

	"github.com/aarock1234/fphttp/v2/internal/releasefetch"
)

// mapBounded calls work for every item, at most limit at a time, and
// returns the results in input order. Work reports its own failures in its
// result, so one item never stops the others.
//
// Once ctx ends it starts no further calls; the results of items it never
// started are zero, and the caller checks ctx. It waits for every started
// call before returning.
func mapBounded[T, R any](
	ctx context.Context,
	items []T,
	limit int,
	work func(context.Context, T) R,
) []R {
	results := make([]R, len(items))
	slots := releasefetch.NewSemaphore(limit)

	var workers sync.WaitGroup

	for index, item := range items {
		if slots.Acquire(ctx) != nil {
			break
		}

		workers.Go(func() {
			defer slots.Release()

			results[index] = work(ctx, item)
		})
	}

	workers.Wait()

	return results
}
