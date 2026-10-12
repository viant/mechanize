package vault

import "context"

// TransitionDOM is a privacy capability transition, never cleanup, login proof,
// or effect reconciliation. The trusted host resolver must independently prove
// a freshly qualified same-origin top document, retired private executor and persistent secret
// redaction. SPA documents may retain their document ID; the navigation/authority
// identity must still change. Durable attempt rows remain held.
func (l *DeliveryLease) TransitionDOM(ctx context.Context, b Binding, resolve func(context.Context) (Binding, error)) (Binding, *DeliveryLease, error) {
	if !l.owns(ctx, b) || resolve == nil {
		return Binding{}, nil, ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery != l || l.retired || (!l.submitted && !l.manualStaging) || l.inFlight != 0 || l.domReaders != 0 || g.readers != 0 || ctx.Err() != nil {
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
	if e != nil || !next.valid() || !nativeRevision(next.NavigationID) || next.SessionID != b.SessionID || next.Target != b.Target || next.NavigationID == b.NavigationID || ctx.Err() != nil {
		return Binding{}, nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.delivery != l || l.retired {
		return Binding{}, nil, ErrUnavailable
	}
	n := &DeliveryLease{gate: g, namespace: l.namespace, clientID: l.clientID, consent: l.consent, binding: next, admit: l.admit, cleanup: l.cleanup, attempted: !l.manualStaging, submitted: !l.manualStaging, domOnly: true}
	l.retired = true
	g.delivery = n
	return next, n, nil
}

// AcquireDOM retains only the promoted exact document capability. It deliberately
// does not increment ordinary exposure readers or remove g.delivery. Screenshots,
// recording, native access and other documents still fail at their normal gates.
// The host must pass the backend's fresh opaque redaction-proof verifier.
func (l *DeliveryLease) AcquireDOM(ctx context.Context, b Binding, verify func(context.Context) error) (func(), error) {
	if !l.owns(ctx, b) || verify == nil {
		return nil, ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	if g.delivery != l || l.retired || !l.domOnly || l.inFlight != 0 || ctx.Err() != nil {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	l.domReaders++
	g.mu.Unlock()
	var released bool
	release := func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if !released {
			released = true
			l.domReaders--
		}
	}
	if deliveryCall(func() error { return verify(ctx) }) != nil || ctx.Err() != nil {
		release()
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	valid := g.delivery == l && !l.retired && l.domOnly
	g.mu.Unlock()
	if !valid {
		release()
		return nil, ErrUnavailable
	}
	return release, nil
}

// VerifyDOM proves retained exact DOM-only exposure, never input or ordinary
// desktop exposure. It is safe for a backend's persistent proof admission guard
// between individual DOM operations; fresh backend redaction proof is separate.
func (l *DeliveryLease) VerifyDOM(ctx context.Context, b Binding) error {
	if !l.owns(ctx, b) {
		return ErrUnavailable
	}
	g := l.gate
	g.mu.Lock()
	defer g.mu.Unlock()
	if ctx.Err() != nil || g.delivery != l || l.retired || !l.domOnly {
		return ErrUnavailable
	}
	return nil
}
