package vault

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/viant/mechanize/auth"
)

var ErrDeliveryProtected = errors.New("automation unavailable while credential delivery is protected")

func deliveryCall(call func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	if call() != nil {
		return ErrUnavailable
	}
	return nil
}

// DeliveryLease excludes ordinary exposure during private browser delivery.
// It is distinct from native credential creation: the original automation
// principal remains the reader. Host adapters must persist the original unknown
// effect before delivery and restore protection after restart; this gate alone
// is not durable evidence or a browser cleanup provider.
type DeliveryLease struct {
	gate                *ExposureGate
	namespace, clientID string
	consent             auth.ConsentBinding
	binding             Binding
	admit, cleanup      func(context.Context) error
	retired             bool
	attempted           bool
	submitted           bool
	domOnly             bool
	manualStaging       bool
	domReaders          int
	inFlight            int
}

func (DeliveryLease) String() string   { return "[private delivery lease withheld]" }
func (DeliveryLease) GoString() string { return "[private delivery lease withheld]" }
func (DeliveryLease) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private delivery lease withheld]")
}
func (DeliveryLease) MarshalJSON() ([]byte, error) { return nil, ErrUnavailable }

func (g *ExposureGate) BeginDelivery(ctx context.Context, binding Binding, admit, cleanup func(context.Context) error) (*DeliveryLease, error) {
	p, err := auth.FromContext(ctx)
	c, ok := auth.ConsentBindingFromContext(ctx)
	if err != nil || p.ClientID == "" || !p.HasScope("desktop:control") || !ok || c.GrantID == "" || c.Purpose == "" || c.SessionID != binding.SessionID {
		return nil, auth.ErrUnauthorized
	}
	if g == nil || g.checkExposure == nil || !binding.valid() || admit == nil || cleanup == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	// ConsentBinding is caller intent. Only the trusted host callback may verify
	// the real durable grant, current recipient and original committed attempt.
	if deliveryCall(func() error { return admit(ctx) }) != nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entry != nil || g.delivery != nil || g.readers != 0 {
		return nil, ErrBusy
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if deliveryCall(func() error { return g.checkExposure(ctx) }) != nil {
		return nil, ErrUnavailable
	}
	l := &DeliveryLease{gate: g, namespace: p.Namespace, clientID: p.ClientID, consent: c, binding: binding, admit: admit, cleanup: cleanup}
	g.delivery = l
	return l, nil
}

func (l *DeliveryLease) owns(ctx context.Context, binding Binding) bool {
	p, err := auth.FromContext(ctx)
	c, ok := auth.ConsentBindingFromContext(ctx)
	return l != nil && l.gate != nil && err == nil && ok && p.HasScope("desktop:control") && p.Namespace == l.namespace && p.ClientID == l.clientID && c == l.consent && binding == l.binding
}

// WithDelivery admits one action for the exact original principal/session/document. A
// failed admission cannot release protection; arbitrary backend errors never
// become public diagnostics from this boundary.
func (l *DeliveryLease) WithDelivery(ctx context.Context, binding Binding, action func() error) error {
	if !l.owns(ctx, binding) {
		return auth.ErrUnauthorized
	}
	if action == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery != l || l.retired || l.attempted {
		g.mu.Unlock()
		return ErrUnavailable
	}
	if l.inFlight != 0 || l.domReaders != 0 || g.readers != 0 {
		g.mu.Unlock()
		return ErrBusy
	}
	l.inFlight++
	g.mu.Unlock()
	defer func() { g.mu.Lock(); l.inFlight--; g.mu.Unlock() }()
	if deliveryCall(func() error { return l.admit(ctx) }) != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	ready := g.delivery == l && !l.retired && !l.attempted && !l.manualStaging && !l.domOnly
	if ready {
		l.attempted = true
	} // Consume before action: a lost reply cannot replay.
	g.mu.Unlock()
	if !ready {
		return ErrUnavailable
	}
	if deliveryCall(action) != nil {
		return ErrUnavailable
	}
	return nil
}

// Verify checks the retained exposure capability for trusted host admission.
// During a one-shot action it remains valid for private freshness/consent probes;
// retirement, completion and cleanup forbid any new secret dispatch. It grants
// no consent and never admits ordinary observation, capture or recording.
func (l *DeliveryLease) Verify(ctx context.Context, binding Binding) error {
	if !l.owns(ctx, binding) {
		return auth.ErrUnauthorized
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.delivery != l || l.retired || l.attempted && l.inFlight != 1 {
		return ErrUnavailable
	}
	return nil
}

func (l *DeliveryLease) Retire() {
	if l == nil || l.gate == nil {
		return
	}
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	if l.gate.delivery == l {
		l.retired = true
	}
}

// Close requires independent trusted cleanup, not dispatch success or expiry.
// Failed cleanup and in-flight work retain the exclusive exposure block.
func (l *DeliveryLease) Close(ctx context.Context) error {
	if l == nil || !l.owns(ctx, l.binding) {
		return auth.ErrUnauthorized
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery != l {
		g.mu.Unlock()
		return ErrEntryCleanup
	}
	l.retired = true
	if l.inFlight != 0 || l.domReaders != 0 || g.readers != 0 {
		g.mu.Unlock()
		return ErrBusy
	}
	// Reserve cleanup so concurrent close cannot race a release/new delivery.
	l.inFlight++
	g.mu.Unlock()
	err := ctx.Err()
	if err == nil {
		err = deliveryCall(func() error { return l.cleanup(ctx) })
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	l.inFlight--
	if err != nil || ctx.Err() != nil || g.delivery != l {
		return ErrEntryCleanup
	}
	g.delivery = nil
	return nil
}

// WithSubmit protects one private exact-form submission after a consumed fill.
// The host must reserve a distinct durable unknown attempt inside action before
// renderer I/O. Consuming this slot precedes action, including failed admission.
func (l *DeliveryLease) WithSubmit(ctx context.Context, b Binding, action func() error) error {
	if !l.owns(ctx, b) || action == nil {
		return ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery != l || l.retired || !l.attempted || l.submitted || l.domOnly || l.inFlight != 0 || g.readers != 0 || ctx.Err() != nil {
		g.mu.Unlock()
		return ErrUnavailable
	}
	l.submitted = true
	l.inFlight = 1
	g.mu.Unlock()
	defer func() { g.mu.Lock(); l.inFlight = 0; g.mu.Unlock() }()
	if deliveryCall(func() error { return l.admit(ctx) }) != nil {
		return ErrUnavailable
	}
	return deliveryCall(action)
}

// AdvancePrivate keeps exposure continuously held while the trusted host proves
// a new same-origin document through the retained authenticated private channel.
// No old attempt is reset: a successful proof creates a new one-shot lease.
// Read-only failures retain the old protection and cannot retry fill or submit.
func (l *DeliveryLease) AdvancePrivate(ctx context.Context, b Binding, resolve func(context.Context) (Binding, error)) (Binding, *DeliveryLease, error) {
	if !l.owns(ctx, b) || resolve == nil {
		return Binding{}, nil, ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery != l || l.retired || !l.submitted || l.domOnly || l.inFlight != 0 || g.readers != 0 || ctx.Err() != nil {
		g.mu.Unlock()
		return Binding{}, nil, ErrUnavailable
	}
	l.inFlight = 1
	g.mu.Unlock()
	defer func() { g.mu.Lock(); l.inFlight = 0; g.mu.Unlock() }()
	if deliveryCall(func() error { return l.admit(ctx) }) != nil {
		return Binding{}, nil, ErrUnavailable
	}
	next, e := resolve(ctx)
	if e != nil || !next.valid() || !nativeRevision(next.NavigationID) || next.SessionID != b.SessionID || next.Target != b.Target || next.DocumentID == b.DocumentID || next.NavigationID == b.NavigationID || ctx.Err() != nil {
		return Binding{}, nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.delivery != l || l.retired {
		return Binding{}, nil, ErrUnavailable
	}
	n := &DeliveryLease{gate: g, namespace: l.namespace, clientID: l.clientID, consent: l.consent, binding: next, admit: l.admit, cleanup: l.cleanup}
	l.retired = true
	g.delivery = n
	return next, n, nil
}
