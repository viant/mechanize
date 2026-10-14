package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

type windowFramePermit struct {
	principal  auth.Principal
	binding    auth.ConsentBinding
	surface    model.Surface
	frame      native.WindowFrameCapture
	admission  NativeControlAdmission
	lease      *consent.Lease
	cancel     context.CancelFunc
	stopOwner  func() bool
	used       bool
	ready      bool
	retiring   bool
	done       chan struct{}
	doneOnce   sync.Once
	cleanupErr error
}

func framePermitRejected(message string) error {
	return &model.MechanizeError{Code: "staleFramePermit", Message: message, Stage: "native", DispatchState: "notDispatched", EffectState: "none"}
}

// CaptureWindowFrame reserves a single control interval on the qualified helper,
// publishes encrypted PNG/provenance, and returns a dedicated expiring permit.
// An ordinary artifact ID is never interpreted as input authority.
func (h *Host) CaptureWindowFrame(ctx context.Context, requested auth.Principal, surface model.Surface, pid int32, windowID uint32) (imageRef data.ArtifactReference, provenanceRef data.ArtifactReference, frame native.WindowFrameCapture, err error) {
	phase := "identity"
	primaryCode := ""
	var record *windowFramePermit
	defer func() {
		if err == nil || imageRef.ID != "" {
			return
		}
		clean := (record == nil || record.cleanupErr == nil) && !errors.Is(err, ErrNativeControlCleanupUnknown)
		if primaryCode == "" {
			primaryCode = windowFrameFailureCode(err)
		}
		dispatch := "notDispatched"
		var transport *native.TransportError
		if errors.As(err, &transport) {
			dispatch = transport.DispatchState
		}
		err = &native.CaptureError{Cause: err, CleanupConfirmed: clean, DispatchState: dispatch, Phase: phase, CauseCode: primaryCode}
	}()
	p, err := h.capturePrincipal(ctx, requested, surface)
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	phase = "session"
	if !ok || p.ClientID == "" || p.ClientID != requested.ClientID || !p.HasScope("desktop:control") || !p.HasScope("desktop:observe") || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, binding.SessionID) != nil {
		return imageRef, provenanceRef, frame, auth.ErrUnauthorized
	}
	phase = "identity"
	if surface.ProcessID <= 0 || surface.ProcessID != int(pid) || surface.ProcessStartToken == "" || windowID == 0 || surface.ValidateProcessIdentity() != nil {
		return imageRef, provenanceRef, frame, framePermitRejected("Exact native process birth and physical window required")
	}
	if h.nativeControl == nil || !h.nativeControl.options.WindowFrameClick || h.artifacts == nil || h.durable == nil {
		return imageRef, provenanceRef, frame, captureUnsupported("Capture-bound window clicks are not enrolled")
	}
	phase = "session"
	if err = h.Runtime.CheckSession(ctx, p, binding.SessionID); err != nil {
		return imageRef, provenanceRef, frame, err
	}
	retained, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*native.WindowFramePermitLifetime)
	record = &windowFramePermit{principal: p, binding: binding, surface: surface, cancel: cancel, done: make(chan struct{})}
	owner := h.owner
	if owner == nil {
		owner = h.nativeControl.options.Owner
	}
	if owner != nil {
		record.stopOwner = context.AfterFunc(owner, cancel)
	}
	phase = "reserve"
	if err = h.reserveWindowFrame(ctx, p, record); err != nil {
		cancel()
		if record.stopOwner != nil {
			record.stopOwner()
		}
		return imageRef, provenanceRef, frame, err
	}
	// The request may finish before the click. Consent retains only authenticated
	// values and a bounded owner lifetime, never the original request's input proof.
	succeeded := false
	defer func() {
		if !succeeded {
			primaryCode = windowFrameFailureCode(err)
			err = errors.Join(err, h.retireWindowFrame(record))
			frame = native.WindowFrameCapture{}
		}
	}()
	phase = "observeConsent"
	observe, err := h.AuthorizeOperation(retained, p, surface, false, consent.Observe)
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	defer observe.Release()
	phase = "controlConsent"
	record.lease, err = h.AuthorizeOperation(retained, p, surface, true, consent.Control)
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	captureCtx, captureCancel := context.WithCancel(record.lease.Context)
	stopRequest := context.AfterFunc(ctx, captureCancel)
	stopObserve := context.AfterFunc(observe.Context, captureCancel)
	defer func() { stopRequest(); stopObserve(); captureCancel() }()
	if ctx.Err() != nil || observe.Context.Err() != nil {
		captureCancel()
	}
	phase = "admission"
	record.admission, err = h.admitNativeControl(captureCtx, p)
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	phase = "nativeCapture"
	frame, err = record.admission.Gateway.CaptureWindowFrame(captureCtx, p, surface, windowID)
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	record.frame = frame
	phase = "publication"
	imageRef, err = h.artifacts.publishBound(captureCtx, p, "image/png", bytes.NewReader(frame.PNG))
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	provenance, err := json.Marshal(struct {
		Artifact data.ArtifactReference   `json:"artifact"`
		Permit   native.WindowFramePermit `json:"permit"`
		Binding  auth.ConsentBinding      `json:"consentBinding"`
	}{imageRef, frame.Permit, record.binding})
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	provenanceRef, err = h.artifacts.publishBound(captureCtx, p, "application/json", bytes.NewReader(provenance))
	if err != nil {
		return imageRef, provenanceRef, frame, err
	}
	if captureCtx.Err() != nil || !time.Now().Before(frame.Permit.ExpiresAt) {
		return imageRef, provenanceRef, frame, framePermitRejected("Capture interval expired before publication")
	}
	// Retained control cancellation covers revoke, owner shutdown, and grant expiry.
	h.frameMu.Lock()
	record.ready = true
	h.frameMu.Unlock()
	context.AfterFunc(record.lease.Context, func() { h.expireWindowFrame(record) })
	time.AfterFunc(time.Until(frame.Permit.ExpiresAt), func() { h.expireWindowFrame(record) })
	succeeded = true
	return imageRef, provenanceRef, frame, nil
}

// retireUnusedWindowFrame shares the existing retirement owner with expiry.
// A caller may replace only its own ready, unused interval, never input in flight.
func (h *Host) retireUnusedWindowFrame(ctx context.Context, p auth.Principal, sessionID string) error {
	h.frameMu.Lock()
	old := h.framePermits[p.Namespace]
	if old == nil {
		h.frameMu.Unlock()
		return ctx.Err()
	}
	if !old.ready || old.used || old.retiring || old.principal.Namespace != p.Namespace || old.principal.ClientID != p.ClientID || old.binding.SessionID != sessionID {
		h.frameMu.Unlock()
		return framePermitRejected("An earlier capture interval is still active")
	}
	old.retiring = true
	h.frameMu.Unlock()
	go func() { _ = h.finishWindowFrameRetirement(ctx, old) }()
	select {
	case <-old.done:
		return errors.Join(old.cleanupErr, ctx.Err())
	case <-ctx.Done():
		return errors.Join(ctx.Err(), ErrNativeControlCleanupUnknown)
	}
}

func (h *Host) reserveWindowFrame(ctx context.Context, p auth.Principal, record *windowFramePermit) error {
	if err := h.retireUnusedWindowFrame(ctx, p, record.binding.SessionID); err != nil {
		return err
	}
	h.frameMu.Lock()
	defer h.frameMu.Unlock()
	if h.framesClosed || ctx.Err() != nil {
		return framePermitRejected("Fresh capture admission ended during retirement")
	}
	// Session close and click consumption use this same reservation boundary.
	if err := h.Runtime.CheckSession(ctx, p, record.binding.SessionID); err != nil {
		return err
	}
	if h.framePermits == nil {
		h.framePermits = map[string]*windowFramePermit{}
	}
	if h.framePermits[p.Namespace] != nil {
		return framePermitRejected("A concurrent capture interval is active")
	}
	h.framePermits[p.Namespace] = record
	return nil
}

func (h *Host) inhibitWindowFrames(ctx context.Context) <-chan error {
	h.frameMu.Lock()
	h.framesClosed = true
	records := make([]*windowFramePermit, 0, len(h.framePermits))
	for _, record := range h.framePermits {
		records = append(records, record)
		record.cancel()
		if record.ready && !record.used {
			go func(record *windowFramePermit) { _ = h.retireWindowFrame(record) }(record)
		}
	}
	h.frameMu.Unlock()
	done := make(chan error, 1)
	go func() {
		var failures []error
		for _, record := range records {
			select {
			case <-record.done:
				failures = append(failures, record.cleanupErr)
			case <-ctx.Done():
				done <- errors.Join(append(failures, ctx.Err(), ErrNativeControlCleanupUnknown)...)
				return
			}
		}
		done <- errors.Join(failures...)
	}()
	return done
}

func (h *Host) expireWindowFrame(record *windowFramePermit) {
	h.frameMu.Lock()
	if h.framePermits[record.principal.Namespace] != record || !record.ready {
		h.frameMu.Unlock()
		return
	}
	used := record.used
	h.frameMu.Unlock()
	if used {
		record.cancel()
		return
	} // Current dispatch owns stop/reap after cancellation.
	_ = h.retireWindowFrame(record)
}

func (h *Host) retireWindowFrame(record *windowFramePermit) error {
	h.frameMu.Lock()
	if h.framePermits[record.principal.Namespace] != record || record.retiring {
		h.frameMu.Unlock()
		return nil
	}
	if record.used {
		h.frameMu.Unlock()
		record.cancel()
		return nil
	}
	record.retiring = true
	h.frameMu.Unlock()
	return h.finishWindowFrameRetirement(context.Background(), record)
}

func (h *Host) finishWindowFrameRetirement(ctx context.Context, record *windowFramePermit) error {
	if record.cancel != nil {
		record.cancel()
	}
	if record.stopOwner != nil {
		record.stopOwner()
	}
	// Expiry cleanup cannot stop a newer helper generation admitted afterwards.
	clean := record.admission.Epoch == 0
	var cleanupErr error
	if !clean {
		cleanup, cancel := context.WithTimeout(auth.WithPrincipal(ctx, record.principal), 2*time.Second)
		matched, report, err := h.nativeControl.revokeWindowFrameGeneration(cleanup, record.principal, uint64(record.admission.Epoch))
		cancel()
		clean = !matched && err == nil || err == nil && report.InputInhibited && report.HelperStopped && report.FenceReleased && !report.UnknownInputs
		if !clean {
			binding := record.binding
			if record.lease != nil {
				if actual, ok := auth.ConsentBindingFromContext(record.lease.Context); ok {
					binding = actual
				}
			}
			metadata := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), record.principal), binding)
			bounded, stop := context.WithTimeout(metadata, defaultNativeCleanupPersistenceTimeout)
			cleanupErr = errors.Join(err, ErrNativeControlCleanupUnknown, h.markControlCleanupUnknown(bounded, record.principal))
			stop()
		}
	}
	if clean && record.lease != nil {
		record.lease.Release()
	}
	h.frameMu.Lock()
	if h.framePermits[record.principal.Namespace] == record {
		delete(h.framePermits, record.principal.Namespace)
	}
	h.frameMu.Unlock()
	record.cleanupErr = cleanupErr
	record.complete()
	return cleanupErr
}

func (record *windowFramePermit) complete() {
	if record.done != nil {
		record.doneOnce.Do(func() { close(record.done) })
	}
}

// cancelWindowFrameSession is called only by Runtime after proving ownership
// and closing session admission. Creating/dispatching owners finish their own
// cancellation cleanup; ready idle permits are retired immediately.
func (h *Host) cancelWindowFrameSession(ctx context.Context, p auth.Principal, sessionID string) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	h.frameMu.Lock()
	record := h.framePermits[p.Namespace]
	if record == nil || record.binding.SessionID != sessionID {
		h.frameMu.Unlock()
		return nil
	}
	ready, used := record.ready, record.used
	h.frameMu.Unlock()
	record.cancel()
	if ready && !used {
		go func() { _ = h.retireWindowFrame(record) }()
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	select {
	case <-record.done:
		return record.cleanupErr
	case <-bounded.Done():
		return errors.Join(bounded.Err(), ErrNativeControlCleanupUnknown)
	}
}

func (m *NativeControlManager) revokeWindowFrameGeneration(ctx context.Context, p auth.Principal, generation uint64) (bool, session.CleanupReport, error) {
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || !actual.HasScope("desktop:control") {
		return false, session.CleanupReport{}, auth.ErrUnauthorized
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.held == nil || m.held.lease.Generation != generation {
		return false, session.CleanupReport{}, nil
	}
	if m.held.principal.Namespace != p.Namespace {
		return true, session.CleanupReport{}, auth.ErrUnauthorized
	}
	report, err := m.closeLocked(ctx)
	return true, report, err
}

func (h *Host) consumeWindowFrame(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value, admission NativeControlAdmission) (*consent.Lease, func(), error) {
	intent, err := data.RequireCommittedStepIntent(ctx, p)
	if err != nil {
		return nil, nil, err
	}
	args, err := step.ResolveArguments(values)
	if err != nil {
		return nil, nil, err
	}
	ref, x, y, err := model.WindowFrameClick(args["frameClick"])
	if err != nil {
		return nil, nil, err
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	h.frameMu.Lock()
	record := h.framePermits[p.Namespace]
	if ok && record != nil && record.ready && record.binding.SessionID == binding.SessionID && record.binding.GrantID == binding.GrantID && record.binding.Purpose != binding.Purpose {
		h.frameMu.Unlock()
		return nil, nil, framePermitRejected("Click purpose must equal the purpose returned with the capture permit")
	}
	if !ok || record == nil || !record.ready || record.retiring || record.used || record.frame.Permit.ID != ref || record.principal.Namespace != p.Namespace || record.principal.ClientID != p.ClientID || record.binding != binding || record.surface != step.Target.Surface || record.admission.Gateway != admission.Gateway || record.admission.Epoch != admission.Epoch || intent.LeaseEpoch != admission.Epoch || intent.SessionID != binding.SessionID || record.lease == nil || record.lease.Context.Err() != nil || !time.Now().Before(record.frame.Permit.ExpiresAt) || x >= int64(record.frame.Permit.Width) || y >= int64(record.frame.Permit.Height) {
		h.frameMu.Unlock()
		return nil, nil, framePermitRejected("Fresh same-owner/client/session capture permit and retained fence required")
	}
	record.used = true
	h.frameMu.Unlock()
	// Keep current committed intent, Endly metadata, deadline and owner identity.
	dispatch, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(record.lease.Context, cancel)
	if record.lease.Context.Err() != nil {
		cancel()
	}
	var released atomic.Bool
	lease := &consent.Lease{Context: dispatch, Release: func() { record.lease.Release(); released.Store(true) }}
	finish := func() {
		stop()
		cancel()
		record.cancel()
		if record.stopOwner != nil {
			record.stopOwner()
		}
		h.frameMu.Lock()
		if h.framePermits[p.Namespace] == record {
			delete(h.framePermits, p.Namespace)
		}
		h.frameMu.Unlock()
		if !released.Load() {
			record.cleanupErr = ErrNativeControlCleanupUnknown
		}
		record.complete()
	}
	return lease, finish, nil
}

func windowFrameFailureCode(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, auth.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrNativeControlCleanupUnknown):
		return "nativeCleanupUnknown"
	case errors.Is(err, ErrNativeControlUnqualified):
		return "nativeUnqualified"
	}
	var detail *model.MechanizeError
	if errors.As(err, &detail) {
		if _, code := (&native.CaptureError{Phase: "identity", CauseCode: detail.Code}).Diagnostic(); code != "" {
			return code
		}
	}
	var failure *native.NativeError
	if errors.As(err, &failure) {
		if _, code := (&native.CaptureError{Phase: "nativeCapture", CauseCode: failure.Code}).Diagnostic(); code != "" {
			return code
		}
	}
	return "unavailable"
}
