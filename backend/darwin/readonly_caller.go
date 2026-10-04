package darwin

import (
	"context"
	"errors"
	"sync"
)

// ReadOnlyCaller replaces a stopped observation helper only for a subsequent
// request. It never replays a failed call and grants no input/recording authority.
// Factory must create an authenticated helper with an owner lifetime independent
// of the per-request context. Caller.Close must confirm the helper was reaped.
type ReadOnlyCaller struct {
	lane       chan struct{}
	mu         sync.Mutex
	current    Caller
	factory    func(context.Context) (Caller, error)
	generation uint64
	invalid    bool
	closed     bool
}

func NewReadOnlyCaller(initial Caller, factory func(context.Context) (Caller, error)) (*ReadOnlyCaller, error) {
	if initial == nil || factory == nil {
		return nil, errors.New("initial readonly helper and replacement factory required")
	}
	return &ReadOnlyCaller{lane: make(chan struct{}, 1), current: initial, factory: factory, generation: 1}, nil
}

func (r *ReadOnlyCaller) enter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case r.lane <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *ReadOnlyCaller) leave() { <-r.lane }

// PrepareRead returns the current helper generation. Gateways must discard
// cached helper epochs/observations on a change and obtain a new doctor reply;
// existing target reference epochs must still be checked against fresh evidence.
func (r *ReadOnlyCaller) PrepareRead(ctx context.Context) (uint64, error) {
	if err := r.enter(ctx); err != nil {
		return 0, err
	}
	defer r.leave()
	return r.prepare(ctx)
}
func (r *ReadOnlyCaller) prepare(ctx context.Context) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, errors.New("readonly helper supervisor closed")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !r.invalid {
		return r.generation, nil
	}
	// A teardown error retains the old helper and prevents overlap/replacement.
	if r.current != nil {
		if err := r.current.Close(); err != nil {
			return 0, err
		}
		r.current = nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	next, err := r.factory(ctx)
	if err != nil || next == nil {
		if next != nil {
			r.current = next
			err = errors.Join(err, next.Close())
			if err == nil {
				r.current = nil
			}
		}
		if err == nil {
			err = errors.New("readonly helper factory returned no helper")
		}
		return 0, err
	}
	r.current = next
	r.invalid = false
	r.generation++
	return r.generation, ctx.Err()
}
func readonlyMethod(method string) bool {
	switch method {
	case "doctor", "apps.list", "windows.list", "elements.snapshot", "elements.read", "elements.valueMatches":
		return true
	}
	return false
}
func (r *ReadOnlyCaller) Call(ctx context.Context, request Request) (Reply, error) {
	if !readonlyMethod(request.Method) || request.Lease != nil {
		return Reply{}, nativeError("readonlyMethodDenied", "Observation helper accepts only unleased readonly methods")
	}
	if err := r.enter(ctx); err != nil {
		return Reply{}, err
	}
	defer r.leave()
	if _, err := r.prepare(ctx); err != nil {
		return Reply{}, err
	}
	r.mu.Lock()
	current := r.current
	r.mu.Unlock()
	reply, err := current.Call(ctx, request)
	var transport *TransportError
	if errors.As(err, &transport) {
		r.mu.Lock()
		r.invalid = true
		r.mu.Unlock()
		// Do not replace or dispatch again in this request. A later PrepareRead must
		// confirm Close succeeded before establishing a new helper generation.
		cleanupErr := current.Close()
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}
	return reply, err
}
func (r *ReadOnlyCaller) Close() error {
	r.mu.Lock()
	r.closed = true
	current := r.current
	r.mu.Unlock()
	if current != nil {
		return current.Close()
	}
	return nil
}
