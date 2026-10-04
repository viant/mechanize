package darwin

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

type readonlyFixture struct {
	mu         sync.Mutex
	requests   []Request
	call       func(context.Context, Request) (Reply, error)
	closeError error
	closes     int
}

func (f *readonlyFixture) Call(ctx context.Context, r Request) (Reply, error) {
	f.mu.Lock()
	f.requests = append(f.requests, r)
	f.mu.Unlock()
	if f.call != nil {
		return f.call(ctx, r)
	}
	return Reply{HelperEpoch: "new"}, nil
}
func (f *readonlyFixture) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closes++
	return f.closeError
}
func readRequest(id string) Request {
	return Request{RequestID: id, Method: "elements.snapshot", HelperEpoch: "old", DeadlineRemainingMS: 1000}
}
func TestReadOnlyCallerNeverReplaysCancelledRequest(t *testing.T) {
	old := &readonlyFixture{call: func(context.Context, Request) (Reply, error) {
		return Reply{}, &TransportError{Cause: context.DeadlineExceeded, DispatchState: "unknown"}
	}}
	next := &readonlyFixture{}
	creates := 0
	r, _ := NewReadOnlyCaller(old, func(context.Context) (Caller, error) { creates++; return next, nil })
	defer r.Close()
	if _, err := r.Call(context.Background(), readRequest("failed")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if creates != 0 || len(old.requests) != 1 || len(next.requests) != 0 {
		t.Fatal("failed call was replayed or replacement started eagerly")
	}
	generation, err := r.PrepareRead(context.Background())
	if err != nil || generation != 2 || creates != 1 {
		t.Fatal(generation, err, creates)
	}
	request := readRequest("next")
	if _, err = r.Call(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if len(next.requests) != 1 || next.requests[0].RequestID != "next" || next.requests[0].HelperEpoch != "old" {
		t.Fatal("old request replayed or caller erased stale reference epoch")
	}
}
func TestReadOnlyCallerRejectsMutationRecordingUnknownAndLeases(t *testing.T) {
	f := &readonlyFixture{}
	r, _ := NewReadOnlyCaller(f, func(context.Context) (Caller, error) { t.Fatal("factory invoked"); return nil, nil })
	defer r.Close()
	for _, method := range []string{"elements.replaceText", "elements.press", "elements.submit", "elements.setValue", "elements.focus", "elements.pressKey", "elements.pressSessionKey", "input.key", "input.releaseAll", "app.launch", "app.activate", "capture.image", "record.start", "record.events", "lease.install", "future.read"} {
		if _, err := r.Call(context.Background(), Request{Method: method}); err == nil {
			t.Fatal("method admitted", method)
		}
	}
	if _, err := r.Call(context.Background(), Request{Method: "doctor", Lease: &Lease{}}); err == nil {
		t.Fatal("lease admitted")
	}
	if len(f.requests) != 0 {
		t.Fatal("denied method dispatched")
	}
	for _, method := range []string{"doctor", "apps.list", "windows.list", "elements.snapshot", "elements.read", "elements.valueMatches"} {
		if _, err := r.Call(context.Background(), Request{Method: method}); err != nil {
			t.Fatal(method, err)
		}
	}
}
func TestReadOnlyCallerRequiresConfirmedStopAndHandlesFailedFactory(t *testing.T) {
	old := &readonlyFixture{closeError: errors.New("reap unknown"), call: func(context.Context, Request) (Reply, error) {
		return Reply{}, &TransportError{Cause: errors.New("pipe lost"), DispatchState: "unknown"}
	}}
	creates := 0
	factoryError := errors.New("startup failed")
	r, _ := NewReadOnlyCaller(old, func(context.Context) (Caller, error) { creates++; return nil, factoryError })
	defer r.Close()
	_, _ = r.Call(context.Background(), readRequest("failed"))
	if _, err := r.PrepareRead(context.Background()); err == nil || creates != 0 {
		t.Fatal("replacement before confirmed stop", err, creates)
	}
	old.closeError = nil
	if _, err := r.PrepareRead(context.Background()); !errors.Is(err, factoryError) || creates != 1 {
		t.Fatal(err, creates)
	}
	if _, err := r.Call(context.Background(), readRequest("later")); !errors.Is(err, factoryError) || len(old.requests) != 1 {
		t.Fatal("factory failure reused stopped helper", err)
	}
}
func TestReadOnlyCallerConcurrentRecoveryCreatesOneHelper(t *testing.T) {
	old := &readonlyFixture{call: func(context.Context, Request) (Reply, error) {
		return Reply{}, &TransportError{Cause: errors.New("stopped"), DispatchState: "notDispatched"}
	}}
	next := &readonlyFixture{}
	var creates atomic.Int32
	r, _ := NewReadOnlyCaller(old, func(context.Context) (Caller, error) { creates.Add(1); return next, nil })
	defer r.Close()
	_, _ = r.Call(context.Background(), readRequest("failed"))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			generation, err := r.PrepareRead(context.Background())
			if err != nil || generation != 2 {
				t.Errorf("prepare: %d %v", generation, err)
			}
			if _, err = r.Call(context.Background(), readRequest("fresh")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if creates.Load() != 1 || len(next.requests) != 20 {
		t.Fatal(creates.Load(), len(next.requests))
	}
}
func TestReadOnlyCallerCancelledAdmissionDoesNotCreateOrDispatch(t *testing.T) {
	f := &readonlyFixture{}
	creates := 0
	r, _ := NewReadOnlyCaller(f, func(context.Context) (Caller, error) { creates++; return nil, nil })
	defer r.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Call(ctx, readRequest("cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.PrepareRead(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if creates != 0 || len(f.requests) != 0 {
		t.Fatal("cancelled admission started work")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PrepareRead(context.Background()); err == nil {
		t.Fatal("closed manager reopened")
	}
}
func TestReadOnlyCallerApplicationErrorKeepsHealthyHelper(t *testing.T) {
	f := &readonlyFixture{call: func(context.Context, Request) (Reply, error) {
		return Reply{HelperEpoch: "same"}, errors.New("target not found")
	}}
	creates := 0
	r, _ := NewReadOnlyCaller(f, func(context.Context) (Caller, error) { creates++; return nil, nil })
	defer r.Close()
	_, _ = r.Call(context.Background(), readRequest("first"))
	generation, err := r.PrepareRead(context.Background())
	if err != nil || generation != 1 || creates != 0 || f.closes != 0 {
		t.Fatal("application error restarted helper")
	}
}

func TestReadOnlyCallerCancelledQueuedRequestNeverDispatches(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := &readonlyFixture{call: func(context.Context, Request) (Reply, error) {
		close(entered)
		<-release
		return Reply{HelperEpoch: "same"}, nil
	}}
	r, _ := NewReadOnlyCaller(f, func(context.Context) (Caller, error) { t.Fatal("unexpected factory"); return nil, nil })
	defer r.Close()
	done := make(chan struct{})
	go func() { defer close(done); _, _ = r.Call(context.Background(), readRequest("active")) }()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Call(ctx, readRequest("queued")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	close(release)
	<-done
	if len(f.requests) != 1 || f.requests[0].RequestID != "active" {
		t.Fatal("cancelled queued request dispatched")
	}
}
