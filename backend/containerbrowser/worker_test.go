package containerbrowser

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func workerFixture(t *testing.T) *Worker {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for worker transport tests")
	}
	w, err := Start(context.Background(), node, "testdata/worker.mjs", nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}
func TestConcurrentRepliesPreserveSession(t *testing.T) {
	w := workerFixture(t)
	var group sync.WaitGroup
	for _, id := range []string{"slow", "fast"} {
		group.Add(1)
		go func() {
			defer group.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			raw, err := w.Call(ctx, "echo", id, nil)
			if err != nil {
				t.Error(err)
				return
			}
			var result struct{ Session string }
			if err = json.Unmarshal(raw, &result); err != nil || result.Session != id {
				t.Errorf("wrong routed result: %s, %v", raw, err)
			}
		}()
	}
	group.Wait()
}
func TestWorkerErrorsAndCancellation(t *testing.T) {
	w := workerFixture(t)
	_, err := w.Call(context.Background(), "error", "s", nil)
	var typed *WorkerError
	if !errors.As(err, &typed) || typed.Code != "deadline" || typed.Outcome != "unknown" {
		t.Fatalf("lost error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = w.Call(ctx, "hang", "s", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost deadline: %v", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) != 0 {
		t.Fatal("pending callback leaked")
	}
}
func TestWorkerExitFailsPendingRequest(t *testing.T) {
	w := workerFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := w.Call(ctx, "exit", "s", nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("exit error: %v", err)
	}
}
