package vault

import (
	"context"
	"github.com/viant/mechanize/auth"
)

// BeginManualDOMTransition is exclusive, no-input staging for a host-proven
// retired source tab. It never opens ordinary exposure or revives a secret lease.
// The trusted host proves owned durable known-input provenance and actual source
// absence before calling; independent persistent redaction must still transition.
func (g *ExposureGate) BeginManualDOMTransition(ctx context.Context, b Binding, admit func(context.Context) error) (*DeliveryLease, error) {
	p, e := auth.FromContext(ctx)
	cb, ok := auth.ConsentBindingFromContext(ctx)
	if g == nil || e != nil || !ok || auth.NativeHuman(ctx) || p.ClientID == "" || !p.HasScope("desktop:control") || cb.GrantID == "" || cb.Purpose == "" || b.SessionID != cb.SessionID || !b.valid() || !nativeRevision(b.NavigationID) || admit == nil || ctx.Err() != nil || deliveryCall(func() error { return admit(ctx) }) != nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entry != nil || g.readers != 0 {
		return nil, ErrDeliveryProtected
	}
	if old := g.delivery; old != nil {
		if old.namespace != p.Namespace || old.clientID != p.ClientID || old.binding.Target != b.Target || !old.retired || old.inFlight != 0 || old.domReaders != 0 {
			return nil, ErrDeliveryProtected
		}
	}
	l := &DeliveryLease{gate: g, namespace: p.Namespace, clientID: p.ClientID, consent: cb, binding: b, admit: admit, cleanup: func(context.Context) error { return ErrEntryCleanup }, manualStaging: true}
	g.delivery = l
	return l, nil
}
