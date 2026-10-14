package main

import (
	"context"
	"sync"
)

// fanOutLimit bounds the calls that one mapConcurrently runs at once. The
// fetcher separately bounds network requests across every fan-out.
const fanOutLimit = 8

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

// mapConcurrently calls work for every item, at most fanOutLimit at a time,
// and returns the results in input order.
//
// After the first failure or cancellation it starts no further calls and
// cancels the context of the running ones. It waits for every started call
// before returning, and then returns the first failure or ctx's cause.
func mapConcurrently[T, R any](
	ctx context.Context,
	items []T,
	work func(context.Context, T) (R, error),
) ([]R, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	results := make([]R, len(items))
	slots := make(semaphore, fanOutLimit)

	var workers sync.WaitGroup

	for index, item := range items {
		if slots.acquire(ctx) != nil {
			break
		}

		workers.Go(func() {
			defer slots.release()

			result, err := work(ctx, item)
			if err != nil {
				cancel(err)
				return
			}

			results[index] = result
		})
	}

	workers.Wait()

	if err := context.Cause(ctx); err != nil {
		return nil, err
	}

	return results, nil
}
