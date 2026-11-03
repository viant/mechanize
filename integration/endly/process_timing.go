package endly

import (
	"context"
	"sync"
	"time"
)

// ProcessTiming measures signed-peer verification only. It carries no authority,
// process identifiers, arguments, values or error text.
type ProcessTiming struct {
	Checks       int64 `json:"checks"`
	Milliseconds int64 `json:"milliseconds"`
}
type processTimingKey struct{}
type processTimingCollector struct {
	mu      sync.Mutex
	checks  int64
	elapsed time.Duration
}

// WithProcessTiming starts an isolated collector for one durable step. The
// snapshot is a copy, so late callbacks cannot modify persisted evidence.
func WithProcessTiming(ctx context.Context) (context.Context, func() ProcessTiming) {
	c := &processTimingCollector{}
	return context.WithValue(ctx, processTimingKey{}, c), func() ProcessTiming {
		c.mu.Lock()
		defer c.mu.Unlock()
		return ProcessTiming{Checks: c.checks, Milliseconds: c.elapsed.Milliseconds()}
	}
}

// RecordProcessVerification records completed full-verification probes. Fast
// continuity checks are deliberately excluded, including their trust decisions.
func RecordProcessVerification(ctx context.Context, elapsed time.Duration) {
	c, _ := ctx.Value(processTimingKey{}).(*processTimingCollector)
	if c == nil || elapsed < 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	c.elapsed += elapsed
}
