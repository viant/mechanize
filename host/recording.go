package host

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
)

// The passive native recorder owns its signed process and bounded stop/drain.
// It has no keyboard, pointer or physical desktop-fence authority.
type nativeRecordingBackend interface {
	Start(context.Context, auth.Principal, auth.ConsentBinding, string, *consent.Lease, int64, int) (record.RecordBatch, error)
	Pause(context.Context, auth.Principal, string) (record.RecordBatch, error)
	Stop(context.Context, auth.Principal, string) (record.RecordBatch, error)
	Events(context.Context, auth.Principal, string, uint64, int) (record.RecordBatch, error)
	Finish(context.Context, auth.Principal, string) error
	Close(context.Context) error
}

type recordingBinding struct {
	mu             sync.Mutex
	principal      auth.Principal
	binding        auth.ConsentBinding
	surface        model.Surface
	lease          *consent.Lease
	durationCancel context.CancelFunc
	stopped        bool
}

// RecordingAllowed is an enrollment ceiling, never a recording approval.
type recordingBackend struct {
	host     *Host
	mu       sync.Mutex
	bindings map[string]*recordingBinding
}

func recordingBindingKey(p auth.Principal, id string) string { return p.Namespace + ":" + id }

func (b *recordingBackend) StartRecording(ctx context.Context, p auth.Principal, s model.Surface, id string) (record.RecordBatch, error) {
	return b.StartRecordingWithLimits(ctx, p, s, id, 900000, 4096)
}
func (b *recordingBackend) StartRecordingWithLimits(ctx context.Context, p auth.Principal, s model.Surface, id string, duration int64, maxEvents int) (record.RecordBatch, error) {
	u, err := b.host.authorize(ctx, p)
	if err != nil {
		return record.RecordBatch{}, err
	}
	if !u.RecordingAllowed || duration < 1000 || duration > 900000 || maxEvents < 1 || maxEvents > 4096 {
		return record.RecordBatch{}, auth.ErrUnauthorized
	}
	switch s.Kind {
	case "desktop":
		if !u.DesktopAccess || b.host.nativeRecording == nil {
			return record.RecordBatch{}, errors.New("enrolled desktop recording backend unavailable")
		}
		if _, err := ConsentScope(s); err != nil {
			return record.RecordBatch{}, err
		}
	case "web":
		allowed := u.DesktopAccess
		for _, origin := range u.WebOrigins {
			allowed = allowed || origin == s.Origin
		}
		if !allowed || b.host.chrome == nil {
			return record.RecordBatch{}, auth.ErrUnauthorized
		}
	default:
		return record.RecordBatch{}, errors.New("recording requires exact desktop or scoped web surface")
	}
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if !ok || p.ClientID == "" {
		return record.RecordBatch{}, auth.ErrUnauthorized
	}
	key := recordingBindingKey(p, id)
	entry := &recordingBinding{principal: p, binding: binding, surface: s}
	b.mu.Lock()
	if b.bindings == nil {
		b.bindings = map[string]*recordingBinding{}
	}
	if b.bindings[key] != nil || len(b.bindings) >= 16 {
		b.mu.Unlock()
		return record.RecordBatch{}, errors.New("recording capacity or ownership conflict")
	}
	b.bindings[key] = entry
	b.mu.Unlock()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	failed := true
	defer func() {
		if failed {
			b.mu.Lock()
			delete(b.bindings, key)
			b.mu.Unlock()
		}
	}()
	owned := auth.WithConsentBinding(auth.WithPrincipal(b.host.owner, p), binding)
	owned, entry.durationCancel = context.WithDeadline(owned, time.Now().Add(time.Duration(duration)*time.Millisecond))
	entry.lease, err = b.host.AuthorizeOperation(owned, p, s, true, consent.Record)
	if err != nil {
		entry.durationCancel()
		return record.RecordBatch{}, err
	}
	if authorized, ok := auth.ConsentBindingFromContext(entry.lease.Context); ok {
		binding = authorized
		entry.binding = authorized
	}
	var batch record.RecordBatch
	if s.Kind == "desktop" {
		batch, err = b.host.nativeRecording.Start(ctx, p, binding, id, entry.lease, duration, maxEvents)
	} else {
		raw, callErr := b.host.chrome.StartRecording(entry.lease.Context, p, s, id)
		batch, err = chromeRecordingEnvelope(raw, callErr)
	}
	if err != nil {
		// Native Start owns bounded failed-start teardown. Chrome cancellation
		// stops renewal and the extension has a bounded consent expiry.
		if s.Kind == "desktop" && errors.Is(err, ErrNativeRecordingCleanupUnknown) {
			// Keep the owned binding and lease for bounded cleanup/reconciliation.
			failed = false
			return batch, err
		}
		if s.Kind == "web" {
			stopCtx, cancel := context.WithTimeout(auth.WithPrincipal(context.WithoutCancel(ctx), p), 4*time.Second)
			_, _ = b.host.chrome.StopRecording(stopCtx, p, id)
			cancel()
		}
		entry.lease.Release()
		entry.durationCancel()
		return batch, err
	}
	failed = false
	if s.Kind == "web" {
		go b.watchChrome(entry, id)
	}
	return batch, nil
}

func (b *recordingBackend) watchChrome(entry *recordingBinding, id string) {
	<-entry.lease.Context.Done()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.stopped {
		return
	}
	ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), entry.principal), 4*time.Second)
	defer cancel()
	batch, err := b.host.chrome.StopRecording(ctx, entry.principal, id)
	entry.stopped = err == nil && batch.State == "stopped"
}

func chromeRecordingEnvelope(batch chrome.RecordBatch, err error) (record.RecordBatch, error) {
	if err != nil {
		return record.RecordBatch{}, err
	}
	return record.FromChromeBatch(batch)
}
func (b *recordingBackend) owned(ctx context.Context, p auth.Principal, id string) (*recordingBinding, error) {
	if _, err := b.host.authorize(ctx, p); err != nil {
		return nil, err
	}
	actual, err := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	b.mu.Lock()
	entry := b.bindings[recordingBindingKey(p, id)]
	b.mu.Unlock()
	if err != nil || !ok || entry == nil || actual.ClientID != entry.principal.ClientID || p.ClientID != entry.principal.ClientID || binding.SessionID != entry.binding.SessionID {
		return nil, auth.ErrUnauthorized
	}
	return entry, nil
}
func recordingRPCCtx(ctx context.Context, p auth.Principal, lease *consent.Lease) (context.Context, func()) {
	bound, cancel := context.WithCancel(auth.WithPrincipal(ctx, p))
	stop := context.AfterFunc(lease.Context, cancel)
	if expiry, ok := lease.Context.Deadline(); ok {
		bound = chrome.WithRecordingLeaseExpiry(bound, expiry)
	}
	return bound, func() { stop(); cancel() }
}
func (b *recordingBackend) PauseRecording(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	entry, err := b.owned(ctx, p, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.surface.Kind == "desktop" {
		return b.host.nativeRecording.Pause(ctx, p, id)
	}
	raw, err := b.host.chrome.PauseRecording(ctx, p, id)
	return chromeRecordingEnvelope(raw, err)
}
func (b *recordingBackend) StopRecording(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	entry, err := b.owned(ctx, p, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	var batch record.RecordBatch
	if entry.surface.Kind == "desktop" {
		batch, err = b.host.nativeRecording.Stop(ctx, p, id)
	} else {
		raw, callErr := b.host.chrome.StopRecording(ctx, p, id)
		batch, err = chromeRecordingEnvelope(raw, callErr)
	}
	entry.stopped = err == nil && batch.State == "stopped"
	return batch, err
}
func (b *recordingBackend) RecordingEvents(ctx context.Context, p auth.Principal, id string, after uint64, limit int) (record.RecordBatch, error) {
	entry, err := b.owned(ctx, p, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	u, err := b.host.authorize(ctx, p)
	if err != nil || !u.RecordingAllowed {
		return record.RecordBatch{}, auth.ErrUnauthorized
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.surface.Kind == "desktop" {
		if !u.DesktopAccess {
			return record.RecordBatch{}, auth.ErrUnauthorized
		}
		return b.host.nativeRecording.Events(ctx, p, id, after, limit)
	}
	if entry.lease == nil {
		return record.RecordBatch{}, auth.ErrUnauthorized
	}
	if entry.lease.Context.Err() != nil && !entry.stopped {
		// Stop is a cleanup operation and uses a fresh bounded caller context.
		stopCtx, cancel := context.WithTimeout(auth.WithPrincipal(context.WithoutCancel(ctx), p), 4*time.Second)
		raw, stopErr := b.host.chrome.StopRecording(stopCtx, p, id)
		cancel()
		entry.stopped = stopErr == nil && raw.State == "stopped"
		return chromeRecordingEnvelope(raw, stopErr)
	}
	callCtx, cancel := recordingRPCCtx(ctx, p, entry.lease)
	if entry.stopped {
		cancel()
		callCtx = ctx
		cancel = func() {}
	}
	defer cancel()
	raw, callErr := b.host.chrome.RecordingEvents(callCtx, p, id, after, limit)
	return chromeRecordingEnvelope(raw, callErr)
}
func (b *recordingBackend) FinishRecording(ctx context.Context, p auth.Principal, id string) error {
	entry, err := b.owned(ctx, p, id)
	if err != nil {
		return err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.surface.Kind == "desktop" {
		if err := b.host.nativeRecording.Finish(ctx, p, id); err != nil {
			return err
		}
	} else if !entry.stopped {
		return errors.New("recording stop unconfirmed")
	}
	if entry.lease != nil {
		entry.lease.Release()
	}
	if entry.durationCancel != nil {
		entry.durationCancel()
	}
	b.mu.Lock()
	delete(b.bindings, recordingBindingKey(p, id))
	b.mu.Unlock()
	return nil
}
