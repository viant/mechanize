package vault

import (
	"context"
	"fmt"
	"io"

	"github.com/viant/mechanize/auth"
)

// DeliveryPreparation protects the real selected target/session before a browser
// document or renderer lease has been admitted. Its unpinned DeliveryLease never
// escapes. This is a volatile primitive: the host must durably record preparation
// protection BEFORE Pin's first private probe and restore it on startup. A later
// admitted-document reservation cannot stand in for that earlier durable phase.
// No placeholder document/navigation/lease identity is created here.
type DeliveryPreparation struct{ state *deliveryPreparationState }
type deliveryPreparationState struct {
	lease        *DeliveryLease
	target       Target
	pinAttempted bool // guarded by lease.gate.mu
	pinned       bool // guarded by lease.gate.mu
}

func (DeliveryPreparation) String() string   { return "[private delivery preparation withheld]" }
func (DeliveryPreparation) GoString() string { return "[private delivery preparation withheld]" }
func (DeliveryPreparation) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private delivery preparation withheld]")
}
func (DeliveryPreparation) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

// BeginDeliveryPreparation reserves exclusive exposure using actual consent and
// selected target metadata only. admit checks real origin/session consent; it
// must not perform an unprotected browser probe. Pin is the sole probing phase.
func (g *ExposureGate) BeginDeliveryPreparation(ctx context.Context, target Target, admit, cleanup func(context.Context) error) (*DeliveryPreparation, error) {
	actor, err := auth.FromContext(ctx)
	consent, ok := auth.ConsentBindingFromContext(ctx)
	if err != nil || actor.ClientID == "" || !actor.HasScope("desktop:control") || !ok || consent.SessionID == "" || consent.GrantID == "" || consent.Purpose == "" {
		return nil, auth.ErrUnauthorized
	}
	if g == nil || g.checkExposure == nil || target.Validate() != nil || admit == nil || cleanup == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if deliveryCall(func() error { return admit(ctx) }) != nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entry != nil || g.delivery != nil || g.readers != 0 {
		return nil, ErrBusy
	}
	if ctx.Err() != nil || deliveryCall(func() error { return g.checkExposure(ctx) }) != nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	lease := &DeliveryLease{gate: g, namespace: actor.Namespace, clientID: actor.ClientID, consent: consent, admit: admit, cleanup: cleanup}
	stage := &DeliveryPreparation{state: &deliveryPreparationState{lease: lease, target: target}}
	g.delivery = lease
	return stage, nil
}
func (p *DeliveryPreparation) owns(ctx context.Context, target Target) bool {
	if p == nil || p.state == nil || p.state.lease == nil || p.state.lease.gate == nil || target != p.state.target {
		return false
	}
	actor, err := auth.FromContext(ctx)
	consent, ok := auth.ConsentBindingFromContext(ctx)
	return err == nil && ok && actor.HasScope("desktop:control") && actor.Namespace == p.state.lease.namespace && actor.ClientID == p.state.lease.clientID && consent == p.state.lease.consent
}

// Verify proves only held exposure for this exact actor/consent/target. It never
// grants permission, a browser identity, a pinned binding or input authority.
// It remains usable by trusted consent/probe guards during Pin and the returned
// lease's one-shot delivery, without exposing the unpinned lease itself.
func (p *DeliveryPreparation) Verify(ctx context.Context, target Target) error {
	if !p.owns(ctx, target) {
		return auth.ErrUnauthorized
	}
	g, l := p.state.lease.gate, p.state.lease
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx.Err() != nil || g.delivery != l || l.retired || p.state.pinAttempted && !p.state.pinned && l.inFlight == 0 || l.attempted && l.inFlight != 1 {
		return ErrUnavailable
	}
	return nil
}

// Pin invokes the trusted host resolver once while exclusive exposure remains
// held. The resolver must execute actual private browser admission and derive
// navigation identity from that confirmed authority, never caller JSON/booleans.
// Scope validation here is not a substitute for that provider proof or its
// durable preparation record. Any uncertain resolver result retains protection.
func (p *DeliveryPreparation) Pin(ctx context.Context, resolve func(context.Context) (Binding, error)) (Binding, *DeliveryLease, error) {
	if p == nil || p.state == nil || !p.owns(ctx, p.state.target) {
		return Binding{}, nil, auth.ErrUnauthorized
	}
	if resolve == nil || ctx.Err() != nil {
		return Binding{}, nil, ErrUnavailable
	}
	g, l := p.state.lease.gate, p.state.lease
	g.mu.Lock()
	if g.delivery != l || l.retired || p.state.pinAttempted || l.inFlight != 0 || g.readers != 0 {
		g.mu.Unlock()
		return Binding{}, nil, ErrBusy
	}
	p.state.pinAttempted = true
	l.inFlight++
	g.mu.Unlock()
	defer func() { g.mu.Lock(); l.inFlight--; g.mu.Unlock() }()
	var actual Binding
	err := deliveryCall(func() error {
		if ctx.Err() != nil || l.admit(ctx) != nil || p.Verify(ctx, p.state.target) != nil {
			return ErrUnavailable
		}
		var err error
		actual, err = resolve(ctx)
		if err != nil || ctx.Err() != nil || !actual.valid() || !nativeRevision(actual.NavigationID) || actual.SessionID != l.consent.SessionID || actual.Target != p.state.target {
			return ErrUnavailable
		}
		if l.admit(ctx) != nil || ctx.Err() != nil || p.Verify(ctx, p.state.target) != nil {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return Binding{}, nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx.Err() != nil || g.delivery != l || l.retired || l.inFlight != 1 {
		return Binding{}, nil, ErrUnavailable
	}
	l.binding = actual
	p.state.pinned = true
	return actual, l, nil
}
func (p *DeliveryPreparation) Retire() {
	if p != nil && p.state != nil && p.state.lease != nil {
		p.state.lease.Retire()
	}
}

// Close may clean up an unpinned or failed preparation, using only the original
// trusted cleanup provider. Retirement occurs under the same mutex as binding
// assignment, so no concurrent Pin can publish a binding after cleanup starts.
func (p *DeliveryPreparation) Close(ctx context.Context) error {
	if p == nil || p.state == nil || !p.owns(ctx, p.state.target) {
		return auth.ErrUnauthorized
	}
	g, l := p.state.lease.gate, p.state.lease
	g.mu.Lock()
	if g.delivery != l {
		g.mu.Unlock()
		return ErrEntryCleanup
	}
	l.retired = true
	if l.inFlight != 0 || g.readers != 0 {
		g.mu.Unlock()
		return ErrBusy
	}
	g.mu.Unlock()
	return l.Close(ctx)
}

// RecoverRetired applies the same trusted absence and durable retirement proof
// to an unpinned or failed preparation. Retire must be called separately; no
// secret delivery is resumed and unknown outcomes are not rewritten here.
func (p *DeliveryPreparation) RecoverRetired(ctx context.Context, verify, retire func(context.Context) error) error {
	if p == nil || p.state == nil || p.state.lease == nil {
		return ErrUnavailable
	}
	return p.state.lease.RecoverRetired(ctx, verify, retire)
}
