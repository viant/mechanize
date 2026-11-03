package endly

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestProcessTimingIsolatedConcurrentAndSnapshotStable(t *testing.T) {
	ctx, snapshot := WithProcessTiming(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); RecordProcessVerification(ctx, 1500*time.Microsecond) }()
	}
	wg.Wait()
	first := snapshot()
	if first.Checks != 20 || first.Milliseconds != 30 {
		t.Fatalf("lost timing: %+v", first)
	}
	nested, other := WithProcessTiming(ctx)
	RecordProcessVerification(nested, 3*time.Millisecond)
	if snapshot() != first || other().Checks != 1 {
		t.Fatal("step contexts not isolated")
	}
	RecordProcessVerification(ctx, 2*time.Millisecond)
	if first.Checks != 20 || snapshot().Checks != 21 {
		t.Fatal("snapshot mutated by later callback")
	}
	RecordProcessVerification(context.Background(), time.Second)
	RecordProcessVerification(ctx, -time.Second)
	if snapshot().Checks != 21 {
		t.Fatal("unscoped/invalid timing changed collector")
	}
}
