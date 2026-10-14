package main

import (
	"context"
	"sync"
)

// semaphore bounds how many operations run at once. Its capacity is the
// bound.
type semaphore chan struct{}

// acquire takes a slot, waiting until one is free or ctx ends.
func (s semaphore) acquire(ctx context.Context) error {
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// release frees a slot taken by acquire.
func (s semaphore) release() {
	<-s
}

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
	slots := make(semaphore, limit)

	var workers sync.WaitGroup

	for index, item := range items {
		if slots.acquire(ctx) != nil {
			break
		}

		workers.Go(func() {
			defer slots.release()

			results[index] = work(ctx, item)
		})
	}

	workers.Wait()

	return results
}
