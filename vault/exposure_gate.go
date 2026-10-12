package vault

import (
	"context"
	"errors"
	"sync"

	"github.com/viant/mechanize/auth"
)

var ErrEntryProtected = errors.New("automation unavailable while native credential entry is protected")
var ErrEntryCleanup = errors.New("native credential entry cleanup unconfirmed; protection retained")

// ExposureGate prevents entry from overlapping any enrolled observation,
// capture, input or recording. A recorder holds its permit for its whole life.
// Every exposure route must participate before this can be production-qualified.
type ExposureGate struct {
	mu            sync.Mutex
	readers       int
	entry         *EntryLease
	delivery      *DeliveryLease
	checkExposure func(context.Context) error
}

// NewGuardedExposureGate adds independent native window reconciliation to
// every exposure admission, including after a broker restart loses its lease.
func NewGuardedExposureGate(check func(context.Context) error) (*ExposureGate, error) {
	if check == nil {
		return nil, ErrUnavailable
	}
	return &ExposureGate{checkExposure: check}, nil
}

// EntryLease is created by a trusted native lifecycle adapter before UI mounting.
// It never expires into an unprotected state. Disconnect/retirement forbids new
// submission but retains the exposure block until trusted cleanup is verified.
type EntryLease struct {
	gate      *ExposureGate
	namespace string
	clientID  string
	target    Target
	cleanup   func(context.Context) error
	retired   bool
	confirmed bool
	inFlight  int
}

func (g *ExposureGate) AcquireExposure() (func(), error) {
	return g.AcquireExposureContext(context.Background())
}
func (g *ExposureGate) AcquireExposureContext(ctx context.Context) (func(), error) {
	return g.acquireExposure(ctx, false)
}

// AcquireNativeExposureContext separates native interaction from browser
// credential DOM protection. It preserves secure Vault-window reconciliation
// and the full exposure reservation; it neither retires a browser delivery nor
// resolves its input history. Native value-read restrictions remain intact;
// screenshots retain the application's displayed password masking.
func (g *ExposureGate) AcquireNativeExposureContext(ctx context.Context) (func(), error) {
	return g.acquireExposure(ctx, true)
}
func (g *ExposureGate) acquireExposure(ctx context.Context, native bool) (func(), error) {
	if g == nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entry != nil {
		return nil, ErrEntryProtected
	}
	if g.delivery != nil && !native {
		return nil, ErrDeliveryProtected
	}
	if ctx.Err() != nil {
		return nil, nativeProbeFailure(nativeProbeContextExpired)
	}
	if g.checkExposure != nil {
		if err := g.checkExposure(ctx); err != nil {
			if errors.Is(err, ErrEntryProtected) {
				return nil, ErrEntryProtected
			}
			return nil, sanitizeNativeProbeFailure(err)
		}
	}
	g.readers++
	var once sync.Once
	return func() { once.Do(func() { g.mu.Lock(); g.readers--; g.mu.Unlock() }) }, nil
}
func (g *ExposureGate) Begin(ctx context.Context, target Target, verifyCleanup func(context.Context) error) (*EntryLease, error) {
	if !auth.NativeHuman(ctx) {
		return nil, auth.ErrUnauthorized
	}
	namespace, _, err := scoped(ctx, target)
	if err != nil {
		return nil, err
	}
	if g == nil || verifyCleanup == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entry != nil || g.delivery != nil || g.readers != 0 {
		return nil, ErrBusy
	}
	principal, _ := auth.FromContext(ctx)
	lease := &EntryLease{gate: g, namespace: namespace, clientID: principal.ClientID, target: target, cleanup: verifyCleanup, confirmed: true}
	g.entry = lease
	return lease, nil
}
func (g *ExposureGate) WithEntry(ctx context.Context, target Target, action func() error) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	namespace, _, err := scoped(ctx, target)
	if err != nil {
		return err
	}
	if g == nil || action == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	g.mu.Lock()
	lease := g.entry
	principal, _ := auth.FromContext(ctx)
	if lease == nil || lease.retired || !lease.confirmed || lease.namespace != namespace || lease.clientID != principal.ClientID || lease.target != target {
		g.mu.Unlock()
		return ErrUnavailable
	}
	lease.inFlight++
	g.mu.Unlock()
	defer func() { g.mu.Lock(); lease.inFlight--; g.mu.Unlock() }()
	return action()
}
func (l *EntryLease) requireWindowConfirmation() {
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	l.confirmed = false
}
func (l *EntryLease) confirmWindow() error {
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	if l.gate.entry != l || l.retired {
		return ErrUnavailable
	}
	l.confirmed = true
	return nil
}
func (l *EntryLease) bindOrigin(ctx context.Context, origin string) error {
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	if l.gate.entry != l || l.retired || !l.confirmed || l.inFlight != 0 || ctx.Err() != nil {
		return ErrUnavailable
	}
	target := Target{Origin: origin, Account: l.target.Account}
	if target.Validate() != nil {
		return ErrScope
	}
	l.target = target
	return nil
}
func (l *EntryLease) Retire() {
	if l == nil || l.gate == nil {
		return
	}
	l.gate.mu.Lock()
	if l.gate.entry == l {
		l.retired = true
	}
	l.gate.mu.Unlock()
}

// Close requires provider-owned cleanup evidence, not a UI-supplied boolean.
// The verifier must prove fields cleared and protected window absent; it must
// not use an ordinary exposure permit to inspect that private cleanup state.
func (l *EntryLease) Close(ctx context.Context) error {
	if !auth.NativeHuman(ctx) {
		return auth.ErrUnauthorized
	}
	principal, err := auth.FromContext(ctx)
	if err != nil || l == nil || l.gate == nil || principal.Namespace != l.namespace || principal.ClientID != l.clientID {
		return auth.ErrUnauthorized
	}
	g := l.gate
	g.mu.Lock()
	if g.entry != l {
		g.mu.Unlock()
		return ErrEntryCleanup
	}
	l.retired = true
	if l.inFlight != 0 {
		g.mu.Unlock()
		return ErrBusy
	}
	g.mu.Unlock()
	if ctx.Err() != nil || l.cleanup(ctx) != nil {
		return ErrEntryCleanup
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.entry != l || l.inFlight != 0 {
		return ErrEntryCleanup
	}
	g.entry = nil
	return nil
}
