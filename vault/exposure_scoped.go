package vault

import (
	"context"
	"sync"
)

// AcquireScopedWebExposure admits only a host-qualified disjoint web target.
// verify must freshly check every durable protection scope and the supplied
// volatile source binding; an empty binding does not prove source absence.
// It grants no consent or native exposure. Native credential entry remains
// exclusive, and the reader reservation prevents private source transitions.
func (g *ExposureGate) AcquireScopedWebExposure(ctx context.Context, verify func(context.Context, Binding) error) (func(), error) {
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
	if deliveryCall(func() error { return verify(ctx, binding) }) != nil || ctx.Err() != nil {
		release()
		return nil, ErrDeliveryProtected
	}
	g.mu.Lock()
	stable := g.entry == nil && g.delivery == source && ctx.Err() == nil
	if source != nil {
		stable = stable && source.binding == binding && source.retired == retired && source.inFlight == 0
	}
	if stable && g.checkExposure != nil {
		stable = deliveryCall(func() error { return g.checkExposure(ctx) }) == nil && ctx.Err() == nil
	}
	g.mu.Unlock()
	if !stable {
		release()
		return nil, ErrDeliveryProtected
	}
	return release, nil
}
