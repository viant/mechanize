package host

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/record"
)

var ErrNativeRecordingCleanupUnknown = errors.New("passive helper reaping unknown; recording lease retained")

// NativeRecordingHelper is passive: it has no input/action methods. A trusted
// factory may inject fixtures; the default factory performs signed peer launch.
type NativeRecordingHelper interface {
	StartRecording(context.Context, native.RecordingStart) (native.RecordBatch, error)
	RenewRecording(context.Context, string, time.Time) (native.RecordBatch, error)
	PauseRecording(context.Context, string) (native.RecordBatch, error)
	StopRecording(context.Context, string) (native.RecordBatch, error)
	RecordingEvents(context.Context, string, uint64, int) (native.RecordBatch, error)
	Close() error
	WaitStopped(context.Context) error
}
type NativeRecordingOptions struct {
	Owner       context.Context
	HelperPath  string
	Requirement string
	ExpectedUID *uint32
	Factory     func(context.Context, native.Options) (NativeRecordingHelper, error)
	Revalidate  func(context.Context, auth.Principal) error
}
type NativeRecordingManager struct {
	options NativeRecordingOptions
	mu      sync.Mutex
	entries map[string]*nativeRecordingEntry
	closed  bool
}
type nativeRecordingEntry struct {
	mu          sync.Mutex
	principal   auth.Principal
	binding     ConsentBinding
	id          string
	lease       *consent.Lease
	helper      NativeRecordingHelper
	ctx         context.Context
	cancel      context.CancelFunc
	cache       native.RecordBatch
	cacheEvents []native.RecordEvent
	cached      bool
	released    bool
	finalErr    error
	reapErr     error
	done        chan struct{}
	started     chan struct{}
	state       string
}

func NewNativeRecordingManager(options NativeRecordingOptions) (*NativeRecordingManager, error) {
	if options.Owner == nil || options.HelperPath == "" || options.Requirement == "" || options.ExpectedUID == nil {
		return nil, errors.New("trusted passive helper enrollment and owner required")
	}
	uid := *options.ExpectedUID
	options.ExpectedUID = &uid
	if options.Factory == nil {
		options.Factory = func(ctx context.Context, options native.Options) (NativeRecordingHelper, error) {
			return native.NewClient(ctx, options)
		}
	}
	return &NativeRecordingManager{options: options, entries: map[string]*nativeRecordingEntry{}}, nil
}
func recordingPrincipal(ctx context.Context, p auth.Principal) error {
	actual, err := auth.FromContext(ctx)
	if err != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
		return auth.ErrUnauthorized
	}
	return nil
}
func nativeRecordingKey(p auth.Principal, id string) string { return p.Namespace + "\x00" + id }
func recordingManagerID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_", r) {
			return false
		}
	}
	return true
}
func (m *NativeRecordingManager) Start(ctx context.Context, p auth.Principal, binding ConsentBinding, id string, lease *consent.Lease, maxDurationMs int64, maxEvents int) (record.RecordBatch, error) {
	if err := recordingPrincipal(ctx, p); err != nil {
		return record.RecordBatch{}, err
	}
	if !recordingManagerID(id) || binding.SessionID == "" || binding.GrantID == "" || binding.Purpose == "" || lease == nil || lease.Context == nil || lease.Release == nil || lease.Context.Err() != nil || maxDurationMs < 1000 || maxDurationMs > 900000 || maxEvents < 4 || maxEvents > 4096 {
		return record.RecordBatch{}, errors.New("live bound desktop recording lease and limits required")
	}
	held, ok := auth.ConsentBindingFromContext(lease.Context)
	if !ok || held != binding || recordingPrincipal(lease.Context, p) != nil {
		return record.RecordBatch{}, auth.ErrUnauthorized
	}
	expiry, ok := lease.Context.Deadline()
	if !ok || time.Until(expiry) < time.Second {
		return record.RecordBatch{}, errors.New("bounded recording consent deadline required")
	}
	if m.options.Revalidate != nil {
		if err := m.options.Revalidate(ctx, p); err != nil {
			return record.RecordBatch{}, err
		}
	}
	base := auth.WithConsentBinding(auth.WithPrincipal(context.WithoutCancel(m.options.Owner), p), binding)
	helperCtx, cancel := context.WithCancel(base)
	e := &nativeRecordingEntry{principal: p, binding: binding, id: id, lease: lease, ctx: helperCtx, cancel: cancel, started: make(chan struct{}), done: make(chan struct{}), state: "starting"}
	key := nativeRecordingKey(p, id)
	m.mu.Lock()
	if m.closed || m.options.Owner.Err() != nil || len(m.entries) >= 16 || m.entries[key] != nil {
		m.mu.Unlock()
		cancel()
		return record.RecordBatch{}, errors.New("passive recording manager closed, full, or already assigned")
	}
	m.entries[key] = e
	m.mu.Unlock()
	// The cancellation worker begins before launch. It waits until ownership of
	// any partially-created helper is known, then stops/reaps before release.
	go m.watch(e)
	e.mu.Lock()
	owner := native.RecordingOwner{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: binding.SessionID}
	helper, err := m.options.Factory(helperCtx, native.Options{HelperPath: m.options.HelperPath, Requirement: m.options.Requirement, ExpectedUID: m.options.ExpectedUID, AllowRecording: true, RecordingOwner: &owner})
	e.helper = helper
	if err == nil && helper == nil {
		err = errors.New("passive helper factory returned no helper")
	}
	var batch native.RecordBatch
	if err == nil && lease.Context.Err() == nil && m.options.Owner.Err() == nil {
		batch, err = helper.StartRecording(lease.Context, native.RecordingStart{RecordingID: id, MaxEvents: maxEvents, MaxDurationMS: int(maxDurationMs), GrantExpiresAt: recordingRenewalExpiry(lease.Context)})
		if err == nil {
			err = m.accumulate(e, batch)
		}
	} else if err == nil {
		err = errors.New("recording authority ended during helper launch")
	}
	e.state = batch.State
	if err != nil {
		e.state = "stopUnconfirmed"
		e.finalErr = err
	}
	e.mu.Unlock()
	close(e.started)
	if err != nil {
		m.finalize(e, "startUnconfirmed")
		e.mu.Lock()
		released := e.released
		e.mu.Unlock()
		if !released {
			return record.RecordBatch{}, errors.Join(err, ErrNativeRecordingCleanupUnknown)
		}
		return record.RecordBatch{}, err
	}
	return nativeRecordingEnvelope(batch, p, binding.SessionID, *m.options.ExpectedUID)
}
func recordingRenewalExpiry(ctx context.Context) time.Time {
	end := time.Now().Add(25 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(end) {
		end = deadline
	}
	return end
}
func (m *NativeRecordingManager) entry(ctx context.Context, p auth.Principal, id string) (*nativeRecordingEntry, error) {
	if err := recordingPrincipal(ctx, p); err != nil {
		return nil, err
	}
	m.mu.Lock()
	e := m.entries[nativeRecordingKey(p, id)]
	m.mu.Unlock()
	if e == nil || e.principal.ClientID != p.ClientID {
		return nil, auth.ErrUnauthorized
	}
	if binding, ok := auth.ConsentBindingFromContext(ctx); ok && binding.SessionID != e.binding.SessionID {
		return nil, auth.ErrUnauthorized
	}
	return e, nil
}
func (m *NativeRecordingManager) accumulate(e *nativeRecordingEntry, batch native.RecordBatch) error {
	if _, err := nativeRecordingEnvelope(batch, e.principal, e.binding.SessionID, *m.options.ExpectedUID); err != nil {
		return err
	}
	if batch.RecordingID != e.id || len(batch.Events) > 64 || len(batch.Gaps) > 8 || batch.LastSequence > 4096 {
		return errors.New("passive recording source bounds mismatch")
	}
	for _, event := range batch.Events {
		found := false
		for _, existing := range e.cacheEvents {
			if existing.Sequence == event.Sequence {
				if !reflect.DeepEqual(existing, event) {
					return errors.New("passive recording lineage changed")
				}
				found = true
				break
			}
		}
		if !found {
			if len(e.cacheEvents) >= 4096 {
				return errors.New("passive recording cache exceeded")
			}
			e.cacheEvents = append(e.cacheEvents, event)
		}
	}
	sort.Slice(e.cacheEvents, func(i, j int) bool { return e.cacheEvents[i].Sequence < e.cacheEvents[j].Sequence })
	e.cache = batch
	e.cache.Events = nil
	return nil
}
func (m *NativeRecordingManager) Pause(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	e, err := m.entry(ctx, p, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	select {
	case <-e.started:
	case <-ctx.Done():
		return record.RecordBatch{}, ctx.Err()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached {
		return m.cachedPage(e, 0, 64)
	}
	if e.helper == nil {
		return record.RecordBatch{}, errors.New("passive helper unavailable")
	}
	batch, err := e.helper.PauseRecording(ctx, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	if err = m.accumulate(e, batch); err != nil {
		return record.RecordBatch{}, err
	}
	e.state = "paused"
	return nativeRecordingEnvelope(batch, p, e.binding.SessionID, *m.options.ExpectedUID)
}
func (m *NativeRecordingManager) Stop(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	e, err := m.entry(ctx, p, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	select {
	case <-e.started:
	case <-ctx.Done():
		return record.RecordBatch{}, ctx.Err()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached {
		return m.cachedPage(e, 0, 64)
	}
	if e.helper == nil {
		return record.RecordBatch{}, errors.New("passive helper unavailable")
	}
	batch, err := e.helper.StopRecording(ctx, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	if err = m.accumulate(e, batch); err != nil {
		return record.RecordBatch{}, err
	}
	e.state = batch.State
	// Keep the stopped helper/journal and held lease until the service drains all
	// pages and invokes Finish. Stop does not discard trailing event pages.
	return nativeRecordingEnvelope(batch, p, e.binding.SessionID, *m.options.ExpectedUID)
}
func (m *NativeRecordingManager) Events(ctx context.Context, p auth.Principal, id string, after uint64, limit int) (record.RecordBatch, error) {
	if limit < 1 || limit > 64 {
		return record.RecordBatch{}, errors.New("bounded recording page required")
	}
	e, err := m.entry(ctx, p, id)
	if err != nil {
		return record.RecordBatch{}, err
	}
	select {
	case <-e.started:
	case <-ctx.Done():
		return record.RecordBatch{}, ctx.Err()
	}
	if e.lease.Context.Err() != nil || m.options.Owner.Err() != nil {
		m.finalize(e, "consentEnded")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cached {
		return m.cachedPage(e, after, limit)
	}
	if m.options.Revalidate != nil {
		if err = m.options.Revalidate(ctx, p); err != nil {
			go m.finalize(e, "operatorWithdrawn")
			return record.RecordBatch{}, err
		}
	}
	if e.state == "recording" {
		if _, err = e.helper.RenewRecording(ctx, id, recordingRenewalExpiry(e.lease.Context)); err != nil {
			go m.finalize(e, "renewalUnconfirmed")
			return record.RecordBatch{}, err
		}
	}
	batch, err := e.helper.RecordingEvents(ctx, id, after, limit)
	if err != nil {
		return record.RecordBatch{}, err
	}
	if err = m.accumulate(e, batch); err != nil {
		return record.RecordBatch{}, err
	}
	if batch.State == "paused" || batch.State == "stopped" || batch.State == "stopUnconfirmed" {
		e.state = batch.State
	}
	return nativeRecordingEnvelope(batch, p, e.binding.SessionID, *m.options.ExpectedUID)
}
func (m *NativeRecordingManager) cachedPage(e *nativeRecordingEntry, after uint64, limit int) (record.RecordBatch, error) {
	if after > e.cache.LastSequence {
		return record.RecordBatch{}, errors.New("recording cache cursor exceeds tail")
	}
	batch := e.cache
	for _, event := range e.cacheEvents {
		if event.Sequence > after && len(batch.Events) < limit {
			batch.Events = append(batch.Events, event)
		}
	}
	return nativeRecordingEnvelope(batch, e.principal, e.binding.SessionID, *m.options.ExpectedUID)
}
func (m *NativeRecordingManager) watch(e *nativeRecordingEntry) {
	<-e.started
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-e.lease.Context.Done():
			m.cancelAndReap(e, "consentEnded")
			return
		case <-m.options.Owner.Done():
			m.cancelAndReap(e, "ownerStopped")
			return
		case <-ticker.C:
			if m.options.Revalidate == nil {
				continue
			}
			bounded, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 3*time.Second)
			if err := m.options.Revalidate(bounded, e.principal); err != nil {
				cancel()
				m.finalize(e, "operatorWithdrawn")
				return
			}
			e.mu.Lock()
			var err error
			if !e.cached && e.state == "recording" {
				_, err = e.helper.RenewRecording(bounded, e.id, recordingRenewalExpiry(e.lease.Context))
			}
			e.mu.Unlock()
			cancel()
			if err != nil {
				m.finalize(e, "renewalUnconfirmed")
				return
			}
		}
	}
}
func (m *NativeRecordingManager) cancelAndReap(e *nativeRecordingEntry, reason string) {
	for attempt := 0; attempt < 3; attempt++ {
		m.finalize(e, reason)
		e.mu.Lock()
		released := e.released
		e.mu.Unlock()
		if released {
			return
		}
		select {
		case <-e.done:
			return
		case <-time.After(time.Second):
		}
	}
}
func (m *NativeRecordingManager) finalize(e *nativeRecordingEntry, reason string) {
	<-e.started
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.released {
		return
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(e.ctx), 5*time.Second)
	defer cancel()
	confirmed := true
	if e.helper != nil {
		batch, err := e.helper.StopRecording(bounded, e.id)
		if err != nil {
			confirmed = false
		} else if err = m.accumulate(e, batch); err != nil {
			confirmed = false
		} else if batch.State != "stopped" {
			confirmed = false
		}
		// Re-read from zero so cancelled-start and failed-commit paths still retain a
		// bounded complete copy. Source events are immutable; duplicate pages merge.
		cursor := uint64(0)
		for page := 0; page < 65; page++ {
			batch, err = e.helper.RecordingEvents(bounded, e.id, cursor, 64)
			if err != nil || m.accumulate(e, batch) != nil {
				confirmed = false
				break
			}
			if len(batch.Events) == 0 {
				if cursor < batch.LastSequence {
					confirmed = false
				}
				break
			}
			cursor = batch.Events[len(batch.Events)-1].Sequence
			if cursor >= batch.LastSequence {
				break
			}
			if page == 64 {
				confirmed = false
			}
		}
		closeErr := e.helper.Close()
		waitErr := e.helper.WaitStopped(bounded)
		var exited *exec.ExitError
		reaped := waitErr == nil || errors.As(waitErr, &exited) && exited.ProcessState != nil
		if closeErr != nil {
			confirmed = false
		}
		if !reaped {
			e.reapErr = errors.Join(closeErr, waitErr, ErrNativeRecordingCleanupUnknown)
			m.markGap(e, "helperReapUnconfirmed")
			e.cached = true
			return
		}
	}
	e.reapErr = nil
	e.cancel()
	if e.cache.RecordingID == "" {
		e.cache = native.RecordBatch{RecordingID: e.id, Owner: native.RecordingOwner{Namespace: e.principal.Namespace, ClientID: e.principal.ClientID, SessionID: e.binding.SessionID}, State: "stopped", LeaseExpiresUnixMS: time.Now().UnixMilli()}
	}
	if !confirmed {
		m.markGap(e, reason)
	} else {
		e.cache.State = "stopped"
	}
	e.cached = true
	e.released = true
	e.lease.Release()
	close(e.done)
}
func (m *NativeRecordingManager) markGap(e *nativeRecordingEntry, reason string) {
	if e.cache.RecordingID == "" {
		e.cache.RecordingID = e.id
		e.cache.Owner = native.RecordingOwner{Namespace: e.principal.Namespace, ClientID: e.principal.ClientID, SessionID: e.binding.SessionID}
		e.cache.LeaseExpiresUnixMS = time.Now().UnixMilli()
	}
	seq := e.cache.LastSequence
	if seq == 0 {
		seq = 1
	}
	e.cache.Gaps = append(e.cache.Gaps, native.RecordGap{Kind: "gap", Reason: reason, FromSequence: seq, ToSequence: seq, UnknownExtent: true})
	if len(e.cache.Gaps) > 8 {
		e.cache.Gaps = e.cache.Gaps[len(e.cache.Gaps)-8:]
	}
	e.cache.LastSequence = seq
	e.cache.State = "stopUnconfirmed"
	e.cache.Truncated = true
}
func (m *NativeRecordingManager) Finish(ctx context.Context, p auth.Principal, id string) error {
	e, err := m.entry(ctx, p, id)
	if err != nil {
		return err
	}
	m.finalize(e, "finishUnconfirmed")
	e.mu.Lock()
	released := e.released
	failure := errors.Join(e.finalErr, e.reapErr)
	e.mu.Unlock()
	if !released {
		return errors.Join(failure, errors.New("passive helper reaping unconfirmed"))
	}
	m.mu.Lock()
	delete(m.entries, nativeRecordingKey(p, id))
	m.mu.Unlock()
	return failure
}
func (m *NativeRecordingManager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	entries := make([]*nativeRecordingEntry, 0, len(m.entries))
	for _, e := range m.entries {
		entries = append(entries, e)
	}
	m.mu.Unlock()
	var result error
	for _, e := range entries {
		m.finalize(e, "ownerStopped")
		e.mu.Lock()
		if !e.released {
			result = errors.Join(result, fmt.Errorf("passive recording %s helper stop unconfirmed", e.id))
		}
		result = errors.Join(result, e.finalErr, e.reapErr)
		e.mu.Unlock()
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
	}
	return result
}
