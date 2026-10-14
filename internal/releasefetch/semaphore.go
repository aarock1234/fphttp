package releasefetch

import "context"

// Semaphore bounds how many operations run at once. Its capacity is the
// bound.
type Semaphore chan struct{}

// NewSemaphore returns a Semaphore that admits limit operations at once.
func NewSemaphore(limit int) Semaphore {
	return make(Semaphore, limit)
}

// Acquire takes a slot, waiting until one is free or ctx ends.
func (s Semaphore) Acquire(ctx context.Context) error {
	select {
	case s <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot taken by Acquire.
func (s Semaphore) Release() {
	<-s
}
