package vault

import (
	"context"
	"errors"
	"sync"
)

// AcquireScopedWebExposure admits only a host-qualified disjoint web target.
// verify must freshly check every durable protection scope and the supplied
// volatile source binding; an empty binding does not prove source absence.
// It grants no consent or native exposure. Native credential entry remains
// exclusive, and the reader reservation prevents private source transitions.
func (g *ExposureGate) AcquireScopedWebExposure(ctx context.Context, verify func(context.Context, Binding) error) (func(), error) {
	return g.acquireScopedWebExposure(ctx, verify, false)
}

// AcquireScopedWebReadExposure reserves the same delivery/entry exclusion, but
// checks native entry before minting a short-lived sanitized renderer read proof.
// CONTROL callers retain AcquireScopedWebExposure's post-verification check.
func (g *ExposureGate) AcquireScopedWebReadExposure(ctx context.Context, verify func(context.Context, Binding) error) (func(), error) {
	return g.acquireScopedWebExposure(ctx, verify, true)
}

func (g *ExposureGate) acquireScopedWebExposure(ctx context.Context, verify func(context.Context, Binding) error, readOnly bool) (func(), error) {
	if g == nil || verify == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	if g.entry != nil {
		g.mu.Unlock()
		return nil, ErrEntryProtected
	}
	source := g.delivery
	var binding Binding
	var retired bool
	if source != nil {
		if source.inFlight != 0 {
			g.mu.Unlock()
			return nil, ErrDeliveryProtected
		}
		binding, retired = source.binding, source.retired
	}
	g.readers++
	g.mu.Unlock()
	var once sync.Once
	release := func() { once.Do(func() { g.mu.Lock(); g.readers--; g.mu.Unlock() }) }
	if readOnly && g.checkExposure != nil {
		var reason error
		if err := deliveryCall(func() error { reason = g.checkExposure(ctx); return reason }); err != nil || ctx.Err() != nil {
			release()
			return nil, scopedExposureProbeFailure(reason)
		}
	}
	if deliveryCall(func() error { return verify(ctx, binding) }) != nil || ctx.Err() != nil {
		release()
		return nil, ErrDeliveryProtected
	}
	g.mu.Lock()
	stable := g.entry == nil && g.delivery == source && ctx.Err() == nil
	if source != nil {
		stable = stable && source.binding == binding && source.retired == retired && source.inFlight == 0
	}
	var probeError, probeReason error
	if stable && !readOnly && g.checkExposure != nil {
		probeError = deliveryCall(func() error { probeReason = g.checkExposure(ctx); return probeReason })
		stable = probeError == nil && ctx.Err() == nil
	}
	g.mu.Unlock()
	if probeError != nil {
		release()
		return nil, scopedExposureProbeFailure(probeReason)
	}
	if !stable {
		release()
		return nil, ErrDeliveryProtected
	}
	return release, nil
}

// A failed observation is not proof that a private entry or delivery exists.
// Keep actual protection sentinels; never expose provider details.
func scopedExposureProbeFailure(err error) error {
	if errors.Is(err, ErrEntryProtected) {
		return ErrEntryProtected
	}
	if errors.Is(err, ErrDeliveryProtected) {
		return ErrDeliveryProtected
	}
	return ErrUnavailable
}
