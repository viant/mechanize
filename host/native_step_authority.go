package host

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

type nativeStepAuthorityKey struct{}

// The registered consent lease belongs to one synchronous immutable operation.
// Cleanup proof runs before its physical generation and durable intent exist.
type nativeStepAuthority struct {
	mu                       sync.Mutex
	host                     *Host
	principal                auth.Principal
	binding                  auth.ConsentBinding
	metadata                 automation.ExecutionMetadata
	stepHash                 string
	epoch                    int
	lease                    *consent.Lease
	used, retired            bool
	stopContext, stopConsent func() bool
}

func (h *Host) prepareNativeStepExecutor(ctx context.Context, p auth.Principal, step model.Step) (context.Context, int, error) {
	// Captured-frame dispatch already owns an exact registered capture lease.
	if step.Action == "window.clickFrame" {
		epoch, err := h.controlLeaseEpoch(ctx, p)
		return ctx, epoch, err
	}
	metadata, ok := automation.ExecutionFromContext(ctx)
	if !ok || metadata.RunID == "" || metadata.PlanID == "" {
		return ctx, 0, errors.New("native execution identity required before preparation")
	}
	stepHash, err := webStepHash(step)
	if err != nil {
		return ctx, 0, err
	}
	lease, err := h.authorizeNativeControlStep(ctx, p, step)
	if err != nil {
		return ctx, 0, err
	}
	if lease == nil || lease.Context == nil || lease.Release == nil {
		return ctx, 0, auth.ErrUnauthorized
	}
	binding, ok := auth.ConsentBindingFromContext(lease.Context)
	if !ok || binding.GrantID == "" || lease.Context.Err() != nil {
		lease.Release()
		return ctx, 0, auth.ErrUnauthorized
	}
	// Logical recovery may stop a current helper. Only now admit the generation
	// that the immutable intent and actual dispatch will share.
	epoch, err := h.controlLeaseEpoch(lease.Context, p)
	if err != nil {
		lease.Release()
		return ctx, 0, err
	}
	prepared := &nativeStepAuthority{host: h, principal: p, binding: binding, metadata: metadata, stepHash: stepHash, epoch: epoch, lease: lease}
	prepared.stopContext = context.AfterFunc(ctx, prepared.retire)
	prepared.stopConsent = context.AfterFunc(lease.Context, prepared.retire)
	returned := auth.WithConsentBinding(ctx, binding)
	return context.WithValue(returned, nativeStepAuthorityKey{}, prepared), epoch, nil
}
func (a *nativeStepAuthority) consume(ctx context.Context, h *Host, p auth.Principal, step model.Step, epoch int) (*consent.Lease, error) {
	actual, err := auth.FromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	metadata, known := automation.ExecutionFromContext(ctx)
	hash, hashErr := webStepHash(step)
	if err != nil || hashErr != nil || a.host != h || actual.Namespace != a.principal.Namespace || actual.ClientID != a.principal.ClientID || p.Namespace != a.principal.Namespace || p.ClientID != a.principal.ClientID || !bound || binding != a.binding || !known || !reflect.DeepEqual(metadata, a.metadata) || hash != a.stepHash || epoch != a.epoch {
		return nil, session.ErrNoLease
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.used || a.retired || ctx.Err() != nil || a.lease.Context.Err() != nil {
		return nil, session.ErrNoLease
	}
	a.used = true
	if a.stopContext != nil {
		a.stopContext()
	}
	if a.stopConsent != nil {
		a.stopConsent()
	}
	// Consent was registered before intent. Dispatch must retain the CURRENT
	// committed-intent/data scope while remaining cancellable by that lease.
	dispatch, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(a.lease.Context, cancel)
	return &consent.Lease{Context: dispatch, Release: func() {
		stop()
		cancel()
		a.lease.Release()
	}}, nil
}
func (a *nativeStepAuthority) retire() {
	a.mu.Lock()
	if a.used || a.retired {
		a.mu.Unlock()
		return
	}
	a.retired = true
	a.mu.Unlock()
	cleanup, stop := context.WithTimeout(auth.WithConsentBinding(auth.WithPrincipal(context.Background(), a.principal), a.binding), 2*time.Second)
	matched, report, err := a.host.nativeControl.revokeNativeStepGeneration(cleanup, a.principal, uint64(a.epoch))
	stop()
	if err == nil && (!matched || report.InputInhibited && report.HelperStopped && report.FenceReleased && !report.UnknownInputs) {
		a.lease.Release()
		return
	}
	// Keep the registered lease inhibited when physical cleanup is uncertain.
	metadata, cancel := context.WithTimeout(auth.WithConsentBinding(auth.WithPrincipal(context.Background(), a.principal), a.binding), defaultNativeCleanupPersistenceTimeout)
	defer cancel()
	_ = a.host.markControlCleanupUnknown(metadata, a.principal)
}
func (m *NativeControlManager) revokeNativeStepGeneration(ctx context.Context, p auth.Principal, generation uint64) (bool, session.CleanupReport, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !actual.HasScope("desktop:control") {
		return false, session.CleanupReport{}, auth.ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held == nil || m.held.lease.Generation != generation {
		return false, session.CleanupReport{}, nil
	}
	if m.held.principal.Namespace != p.Namespace || m.held.principal.ClientID != p.ClientID {
		return true, session.CleanupReport{}, auth.ErrUnauthorized
	}
	report, err := m.closeLocked(ctx)
	return true, report, err
}
