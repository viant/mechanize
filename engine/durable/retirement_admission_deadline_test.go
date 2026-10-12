package durable

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRetirementAdmissionDeadlineDoesNotWaitForOwnerOrStealLock(t *testing.T) {
	var mutex sync.Mutex
	mutex.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- lockRetirementAdmission(ctx, &mutex) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("deadline not preserved", err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired admission still waits behind owner")
	}
	if mutex.TryLock() {
		mutex.Unlock()
		t.Fatal("cancellation released another owner's lock")
	}
	mutex.Unlock()
	if err := lockRetirementAdmission(context.Background(), &mutex); err != nil {
		t.Fatal(err)
	}
	mutex.Unlock()
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := lockRetirementAdmission(cancelled, &mutex); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !mutex.TryLock() {
		t.Fatal("cancelled request retained lock")
	}
	mutex.Unlock()
}
