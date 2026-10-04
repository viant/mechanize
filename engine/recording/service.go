// Package recording coordinates scoped capture transport and generated Datly components.
package recording

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data/recordevents"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/record"
	"sync"
	"time"
)

type Backend interface {
	StartRecording(context.Context, auth.Principal, model.Surface, string) (record.RecordBatch, error)
	PauseRecording(context.Context, auth.Principal, string) (record.RecordBatch, error)
	StopRecording(context.Context, auth.Principal, string) (record.RecordBatch, error)
	RecordingEvents(context.Context, auth.Principal, string, uint64, int) (record.RecordBatch, error)
}
type BackendWithLimits interface {
	StartRecordingWithLimits(context.Context, auth.Principal, model.Surface, string, int64, int) (record.RecordBatch, error)
}
type BackendFinalizer interface {
	FinishRecording(context.Context, auth.Principal, string) error
}

// LegacyChromeBackend remains a checked compatibility boundary, never the
// common native envelope: native identity fields cannot be decoded into Chrome.
type LegacyChromeBackend interface {
	StartRecording(context.Context, auth.Principal, model.Surface, string) (chrome.RecordBatch, error)
	PauseRecording(context.Context, auth.Principal, string) (chrome.RecordBatch, error)
	StopRecording(context.Context, auth.Principal, string) (chrome.RecordBatch, error)
	RecordingEvents(context.Context, auth.Principal, string, uint64, int) (chrome.RecordBatch, error)
}
type legacyChromeBackend struct{ LegacyChromeBackend }

func legacyBatch(batch chrome.RecordBatch, id string, err error) (record.RecordBatch, error) {
	if err != nil {
		return record.RecordBatch{}, err
	}
	if batch.RecordingID == "" {
		batch.RecordingID = id
	}
	return record.FromChromeBatch(batch)
}
func (b legacyChromeBackend) StartRecording(ctx context.Context, p auth.Principal, surface model.Surface, id string) (record.RecordBatch, error) {
	batch, err := b.LegacyChromeBackend.StartRecording(ctx, p, surface, id)
	return legacyBatch(batch, id, err)
}
func (b legacyChromeBackend) PauseRecording(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	batch, err := b.LegacyChromeBackend.PauseRecording(ctx, p, id)
	return legacyBatch(batch, id, err)
}
func (b legacyChromeBackend) StopRecording(ctx context.Context, p auth.Principal, id string) (record.RecordBatch, error) {
	batch, err := b.LegacyChromeBackend.StopRecording(ctx, p, id)
	return legacyBatch(batch, id, err)
}
func (b legacyChromeBackend) RecordingEvents(ctx context.Context, p auth.Principal, id string, after uint64, limit int) (record.RecordBatch, error) {
	batch, err := b.LegacyChromeBackend.RecordingEvents(ctx, p, id, after, limit)
	return legacyBatch(batch, id, err)
}

// Components invokes authorized generated use cases, with confirmed commit on Append.
type Components interface {
	Append(context.Context, auth.Principal, []*recordevents.RecordedEvent) error
	Read(context.Context, auth.Principal, string) ([]*recordevents.RecordedEvent, error)
}
type ComponentFuncs struct {
	AppendEvents func(context.Context, auth.Principal, []*recordevents.RecordedEvent) error
	ReadEvents   func(context.Context, auth.Principal, string) ([]*recordevents.RecordedEvent, error)
}

func (c ComponentFuncs) Append(ctx context.Context, p auth.Principal, e []*recordevents.RecordedEvent) error {
	return c.AppendEvents(ctx, p, e)
}
func (c ComponentFuncs) Read(ctx context.Context, p auth.Principal, id string) ([]*recordevents.RecordedEvent, error) {
	return c.ReadEvents(ctx, p, id)
}

type StartRequest struct {
	SessionID     string                           `json:"sessionId,omitempty"`
	GrantID       string                           `json:"grantId,omitempty"`
	Purpose       string                           `json:"purpose,omitempty"`
	RecordingID   string                           `json:"recordingId"`
	Surface       model.Surface                    `json:"surface"`
	Consent       bool                             `json:"consent"`
	MaxDurationMs int64                            `json:"maxDurationMs"`
	MaxEvents     int                              `json:"maxEvents"`
	Objective     *model.Predicate                 `json:"objective"`
	Inputs        map[string]model.InputDefinition `json:"inputs,omitempty"`
}
type ExportRequest struct {
	SessionID   string            `json:"sessionId,omitempty"`
	RecordingID string            `json:"recordingId"`
	Parameters  map[uint64]string `json:"parameters,omitempty"`
	Reviewed    bool              `json:"reviewed"`
}
type Status struct {
	RecordingID      string `json:"recordingId"`
	State            string `json:"state"`
	PersistedEvents  int    `json:"persistedEvents"`
	LastSequence     uint64 `json:"lastSequence"`
	CoverageComplete bool   `json:"coverageComplete"`
	Reason           string `json:"reason,omitempty"`
}
type envelope struct {
	Version          int                 `json:"version,omitempty"`
	VerifiedClientID string              `json:"verifiedClientId,omitempty"`
	Kind             string              `json:"kind"`
	Request          *StartRequest       `json:"request,omitempty"`
	Batch            *record.RecordBatch `json:"batch,omitempty"`
	Reason           string              `json:"reason,omitempty"`
}
type session struct {
	mu      sync.Mutex
	p       auth.Principal
	req     StartRequest
	status  Status
	journal int
	end     time.Time
}
type Service struct {
	owner      context.Context
	backend    Backend
	components Components
	mu         sync.Mutex
	sessions   map[string]*session
}

func New(owner context.Context, backend any, c Components) (*Service, error) {
	if owner == nil || backend == nil || c == nil {
		return nil, errors.New("owned context, recording backend and Datly components required")
	}
	var b Backend
	switch provider := backend.(type) {
	case Backend:
		b = provider
	case LegacyChromeBackend:
		b = legacyChromeBackend{provider}
	default:
		return nil, errors.New("common recorder backend or checked legacy Chrome adapter required")
	}
	return &Service{owner: owner, backend: b, components: c, sessions: map[string]*session{}}, nil
}
func key(p auth.Principal, id string) string { return p.Namespace + "\x00" + id }
func authorized(ctx context.Context, p auth.Principal, control bool) error {
	a, e := auth.FromContext(ctx)
	if e != nil || p.Validate() != nil || a.Namespace != p.Namespace || a.ClientID == "" || a.ClientID != p.ClientID || !(a.HasScope("desktop:read") || a.HasScope("desktop:observe") || a.HasScope("desktop:control")) || control && !a.HasScope("desktop:control") {
		return auth.ErrUnauthorized
	}
	return nil
}
func validID(id string) bool {
	if len(id) < 1 || len(id) > 96 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func (s *Service) append(ctx context.Context, r *session, v envelope) error {
	v.Version = 1
	v.VerifiedClientID = r.p.ClientID
	payload, e := json.Marshal(v)
	if e != nil {
		return e
	}
	if len(payload) > 256*1024 {
		return errors.New("recording journal payload bound exceeded")
	}
	seq := r.journal + 1
	if seq > 1024 {
		return errors.New("recording journal entry bound exceeded")
	}
	id := fmt.Sprintf("%s_%d", r.req.RecordingID, seq)
	kind := v.Kind
	text := string(payload)
	created := time.Now().UTC().Format(time.RFC3339Nano)
	row := &recordevents.RecordedEvent{}
	row.SetNamespace(&r.p.Namespace)
	row.SetId(&id)
	row.SetRecordingId(&r.req.RecordingID)
	row.SetSequence(&seq)
	row.SetKind(&kind)
	row.SetPayloadJson(&text)
	row.SetCreatedAt(&created)
	if e = s.components.Append(ctx, r.p, []*recordevents.RecordedEvent{row}); e != nil {
		return e
	}
	r.journal = seq
	return nil
}
func (s *Service) save(ctx context.Context, r *session, b record.RecordBatch) error {
	if b.RecordingID != r.req.RecordingID {
		return errors.New("recording batch ownership lineage mismatch")
	}
	filtered := make([]record.RecordEvent, 0, len(b.Events))
	var previous uint64
	lastKept := r.status.LastSequence
	for _, e := range b.Events {
		if e.RecordingID != r.req.RecordingID || e.Sequence <= previous {
			return errors.New("recording event lineage/sequence invalid")
		}
		previous = e.Sequence
		if err := e.Validate(); err != nil {
			return err
		}
		if e.Sequence <= r.status.LastSequence {
			continue
		}
		expected := lastKept + 1
		if e.Sequence != expected {
			b.Gaps = append(b.Gaps, record.RecordGap{Kind: "gap", Reason: "sequenceGap", FromSequence: expected, ToSequence: e.Sequence - 1, Lost: e.Sequence - expected})
		}
		e.Value = nil
		filtered = append(filtered, e)
		lastKept = e.Sequence
	}
	b.Events = filtered
	if r.status.PersistedEvents+len(b.Events) > r.req.MaxEvents {
		return errors.New("recording event bound exceeded")
	}
	if e := s.append(ctx, r, envelope{Kind: "batch", Batch: &b}); e != nil {
		return e
	}
	r.status.State = b.State
	r.status.PersistedEvents += len(b.Events)
	for _, e := range b.Events {
		r.status.LastSequence = e.Sequence
	}
	if len(b.Gaps) > 0 || b.Truncated {
		r.status.CoverageComplete = false
	}
	return nil
}
func (s *Service) fault(ctx context.Context, r *session, reason string) {
	r.status.State = "interrupted"
	r.status.CoverageComplete = false
	r.status.Reason = reason
	_ = s.append(ctx, r, envelope{Kind: "fault", Reason: reason})
}
func (s *Service) Start(ctx context.Context, p auth.Principal, req StartRequest) (Status, error) {
	if e := authorized(ctx, p, true); e != nil {
		return Status{}, e
	}
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if !bound || binding.SessionID == "" || binding.GrantID == "" || binding.Purpose == "" || req.SessionID != "" && req.SessionID != binding.SessionID || req.GrantID != "" && req.GrantID != binding.GrantID || req.Purpose != "" && req.Purpose != binding.Purpose {
		return Status{}, errors.New("verified recorder client/session/grant binding required")
	}
	req.SessionID = binding.SessionID
	req.GrantID = binding.GrantID
	req.Purpose = binding.Purpose
	validSurface := req.Surface.Kind == "web" && req.Surface.Origin != "" && req.Surface.TabID != "" || req.Surface.Kind == "desktop" && req.Surface.BundleID == "" && req.Surface.Origin == "" && req.Surface.Title == "" && req.Surface.TabID == ""
	if !validID(req.RecordingID) || !req.Consent || !validSurface || req.MaxEvents < 1 || req.MaxEvents > 4096 || req.MaxDurationMs < 1000 || req.MaxDurationMs > 900000 || req.Objective == nil {
		return Status{}, errors.New("explicit consent, desktop or scoped web collection, objective and bounded duration/events required; per-app native transport is unsupported")
	}
	if e := req.Objective.Validate(); e != nil {
		return Status{}, e
	}
	for _, i := range req.Inputs {
		if i.Default != nil {
			return Status{}, errors.New("capture input defaults prohibited")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner.Err() != nil {
		return Status{}, s.owner.Err()
	}
	if len(s.sessions) >= 16 || s.sessions[key(p, req.RecordingID)] != nil {
		return Status{}, errors.New("recording capacity or ID conflict")
	}
	existing, e := s.components.Read(ctx, p, req.RecordingID)
	if e != nil {
		return Status{}, e
	}
	if len(existing) > 0 {
		return Status{}, errors.New("recording ID already persisted")
	}
	p, _ = auth.FromContext(ctx)
	r := &session{p: p, req: req, status: Status{RecordingID: req.RecordingID, State: "starting", CoverageComplete: true}, end: time.Now().Add(time.Duration(req.MaxDurationMs) * time.Millisecond)}
	if e = s.append(ctx, r, envelope{Kind: "intent", Request: &req}); e != nil {
		return Status{}, e
	}
	s.sessions[key(p, req.RecordingID)] = r
	var b record.RecordBatch
	if backend, ok := s.backend.(BackendWithLimits); ok {
		b, e = backend.StartRecordingWithLimits(ctx, p, req.Surface, req.RecordingID, req.MaxDurationMs, req.MaxEvents)
	} else {
		b, e = s.backend.StartRecording(ctx, p, req.Surface, req.RecordingID)
	}
	if e != nil {
		s.fault(ctx, r, "startUnconfirmed")
		return r.status, e
	}
	if e = s.save(ctx, r, b); e != nil {
		s.fault(ctx, r, "persistenceUnconfirmed")
		return r.status, e
	}
	go s.poll(r)
	return r.status, nil
}
func (s *Service) poll(r *session) {
	timer := time.NewTicker(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-s.owner.Done():
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(auth.WithConsentBinding(auth.WithPrincipal(s.owner, r.p), auth.ConsentBinding{SessionID: r.req.SessionID, GrantID: r.req.GrantID, Purpose: r.req.Purpose}), 4*time.Second)
			r.mu.Lock()
			if r.status.State != "recording" {
				r.mu.Unlock()
				cancel()
				return
			}
			err := s.pollLocked(ctx, r)
			done := err != nil || r.status.State != "recording"
			r.mu.Unlock()
			cancel()
			if done {
				return
			}
		}
	}
}
func (s *Service) pollLocked(ctx context.Context, r *session) error {
	if time.Now().After(r.end) || r.status.PersistedEvents >= r.req.MaxEvents {
		return s.controlLocked(ctx, r, true)
	}
	batch, err := s.backend.RecordingEvents(ctx, r.p, r.req.RecordingID, r.status.LastSequence, 64)
	if err != nil {
		s.stopOnFaultLocked(ctx, r, "captureInterrupted")
		return err
	}
	return s.acceptBatchLocked(ctx, r, batch)
}

func (s *Service) live(ctx context.Context, p auth.Principal, id string) (*session, error) {
	if e := authorized(ctx, p, true); e != nil {
		return nil, e
	}
	s.mu.Lock()
	r := s.sessions[key(p, id)]
	s.mu.Unlock()
	if r == nil {
		return nil, errors.New("no live capture ownership; inspect persisted recording")
	}
	if err := recordingOwner(ctx, p, r.p.ClientID, r.req.SessionID); err != nil {
		return nil, err
	}
	return r, nil
}
func (s *Service) control(ctx context.Context, p auth.Principal, id string, stop bool) (Status, error) {
	r, err := s.live(ctx, p, id)
	if err != nil {
		return Status{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	err = s.controlLocked(ctx, r, stop)
	return r.status, err
}
func (s *Service) controlLocked(ctx context.Context, r *session, stop bool) error {
	var batch record.RecordBatch
	var err error
	if stop {
		batch, err = s.backend.StopRecording(ctx, r.p, r.req.RecordingID)
	} else {
		batch, err = s.backend.PauseRecording(ctx, r.p, r.req.RecordingID)
	}
	if err != nil {
		s.stopOnFaultLocked(ctx, r, "controlUnconfirmed")
		return err
	}
	return s.acceptBatchLocked(ctx, r, batch)
}
func (s *Service) acceptBatchLocked(ctx context.Context, r *session, batch record.RecordBatch) error {
	if err := s.save(ctx, r, batch); err != nil {
		s.stopOnFaultLocked(ctx, r, "persistenceUnconfirmed")
		return err
	}
	terminal := batch.State == "stopped" || batch.State == "paused"
	if !terminal {
		return nil
	}
	watermark := batch.LastSequence
	for pages := 0; pages < 64 && r.status.LastSequence < watermark; pages++ {
		next, err := s.backend.RecordingEvents(ctx, r.p, r.req.RecordingID, r.status.LastSequence, 64)
		if err != nil {
			s.stopOnFaultLocked(ctx, r, "drainInterrupted")
			return err
		}
		before := r.status.LastSequence
		if err = s.save(ctx, r, next); err != nil {
			s.stopOnFaultLocked(ctx, r, "persistenceUnconfirmed")
			return err
		}
		if r.status.LastSequence == before {
			break
		}
	}
	if r.status.LastSequence < watermark {
		s.fault(ctx, r, "coverageGap")
		if err := s.finalizeLocked(ctx, r); err != nil {
			return err
		}
		return errors.New("recording drain did not reach the terminal watermark; coverage gap retained")
	}
	// A terminal page may carry 'paused' or 'stopped'; trailing read pages cannot
	// silently change the confirmed source state back into recording.
	r.status.State = batch.State
	if batch.State == "stopped" {
		if err := s.finalizeLocked(ctx, r); err != nil {
			s.fault(ctx, r, "teardownUnconfirmed")
			return err
		}
	}
	return nil
}
func (s *Service) finalizeLocked(ctx context.Context, r *session) error {
	if backend, ok := s.backend.(BackendFinalizer); ok {
		return backend.FinishRecording(ctx, r.p, r.req.RecordingID)
	}
	return nil
}
func (s *Service) stopOnFaultLocked(ctx context.Context, r *session, reason string) {
	// Required persistence failure stops further observation renewal. A fresh
	// bounded identity context permits best-effort stop/reap without pretending
	// that missing journal pages or failed teardown were confirmed.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 4*time.Second)
	defer cancel()
	_, stopErr := s.backend.StopRecording(cleanup, r.p, r.req.RecordingID)
	finishErr := s.finalizeLocked(cleanup, r)
	if stopErr != nil || finishErr != nil {
		reason += ";teardownUnconfirmed"
	}
	s.fault(cleanup, r, reason)
}

func (s *Service) Pause(ctx context.Context, p auth.Principal, id string) (Status, error) {
	return s.control(ctx, p, id, false)
}
func (s *Service) Stop(ctx context.Context, p auth.Principal, id string) (Status, error) {
	return s.control(ctx, p, id, true)
}
func (s *Service) load(ctx context.Context, p auth.Principal, id string) (StartRequest, Status, []record.RecordEvent, []record.RecordGap, error) {
	var req StartRequest
	status := Status{RecordingID: id, State: "interrupted", Reason: "liveStateUnavailable"}
	if e := authorized(ctx, p, false); e != nil {
		return req, status, nil, nil, e
	}
	rows, e := s.components.Read(ctx, p, id)
	if e != nil {
		return req, status, nil, nil, e
	}
	if len(rows) == 0 {
		return req, status, nil, nil, errors.New("recording not found")
	}
	if len(rows) > 10000 {
		return req, status, nil, nil, errors.New("recording reader bound exceeded")
	}
	var events []record.RecordEvent
	var gaps []record.RecordGap
	for i, row := range rows {
		if row.Namespace == nil || *row.Namespace != p.Namespace || row.RecordingId == nil || *row.RecordingId != id || row.Sequence == nil || *row.Sequence != i+1 || row.PayloadJson == nil {
			return req, status, nil, nil, errors.New("invalid scoped recording journal")
		}
		var v envelope
		if e = json.Unmarshal([]byte(*row.PayloadJson), &v); e != nil {
			return req, status, nil, nil, e
		}
		if v.Kind == "intent" {
			if v.Version != 1 || v.Request == nil || v.VerifiedClientID == "" {
				return req, status, nil, nil, errors.New("persisted recording client ownership is unavailable")
			}
			req = *v.Request
			if err := recordingOwner(ctx, p, v.VerifiedClientID, req.SessionID); err != nil {
				return req, status, nil, nil, err
			}
		} else if req.SessionID == "" {
			return req, status, nil, nil, errors.New("recording intent owner missing")
		}
		if v.Batch != nil {
			if v.Batch.RecordingID != id {
				return req, status, nil, nil, errors.New("persisted batch recording lineage mismatch")
			}
			for _, event := range v.Batch.Events {
				if event.RecordingID != id || event.EventSurface == "" {
					return req, status, nil, nil, errors.New("common event surface/lineage missing")
				}
				if err := event.Validate(); err != nil {
					return req, status, nil, nil, err
				}
			}
			events = append(events, v.Batch.Events...)
			gaps = append(gaps, v.Batch.Gaps...)
			if v.Batch.Truncated {
				gaps = append(gaps, record.RecordGap{Kind: "gap", Reason: "truncatedBatch", UnknownExtent: true})
			}
			status.LastSequence = v.Batch.LastSequence
			if v.Batch.State == "stopped" {
				status.State = "stopped"
				status.Reason = ""
			} else {
				status.State = "interrupted"
				status.Reason = "liveStateUnavailable"
			}
		}
		if v.Kind == "fault" {
			status.State = "interrupted"
			status.Reason = v.Reason
			gaps = append(gaps, record.RecordGap{Kind: "gap", Reason: v.Reason, UnknownExtent: true})
		}
	}
	status.PersistedEvents = len(events)
	status.CoverageComplete = len(gaps) == 0 && status.State == "stopped"
	return req, status, events, gaps, nil
}
func (s *Service) Status(ctx context.Context, p auth.Principal, id string) (Status, error) {
	if e := authorized(ctx, p, false); e != nil {
		return Status{}, e
	}
	s.mu.Lock()
	r := s.sessions[key(p, id)]
	s.mu.Unlock()
	if r != nil {
		if err := recordingOwner(ctx, p, r.p.ClientID, r.req.SessionID); err != nil {
			return Status{}, err
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if s.owner.Err() != nil && r.status.State != "stopped" {
			r.status.State = "interrupted"
			r.status.CoverageComplete = false
			r.status.Reason = "captureOwnerEnded"
		}
		return r.status, nil
	}
	_, status, _, _, e := s.load(ctx, p, id)
	return status, e
}
func (s *Service) Export(ctx context.Context, p auth.Principal, input ExportRequest) (record.Export, error) {
	if input.SessionID != "" {
		binding, ok := auth.ConsentBindingFromContext(ctx)
		if !ok || binding.SessionID != input.SessionID {
			return record.Export{}, auth.ErrUnauthorized
		}
	}
	req, status, events, gaps, e := s.load(ctx, p, input.RecordingID)
	if e != nil {
		return record.Export{}, e
	}
	if status.State != "stopped" {
		gaps = append(gaps, record.RecordGap{Kind: "gap", Reason: "stopNotConfirmed", UnknownExtent: true})
	}
	return (record.Compiler{}).Compile(record.Request{Name: input.RecordingID, Surface: req.Surface, Objective: req.Objective, Inputs: req.Inputs, Parameters: input.Parameters, Reviewed: input.Reviewed}, events, gaps)
}

// Close attempts bounded capture stops before the owning server shuts down.
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	sessions := make([]*session, 0, len(s.sessions))
	for _, r := range s.sessions {
		sessions = append(sessions, r)
	}
	s.mu.Unlock()
	var failures []error
	for _, r := range sessions {
		r.mu.Lock()
		done := r.status.State == "stopped"
		r.mu.Unlock()
		if done {
			continue
		}
		bound, cancel := context.WithTimeout(auth.WithConsentBinding(auth.WithPrincipal(ctx, r.p), auth.ConsentBinding{SessionID: r.req.SessionID, GrantID: r.req.GrantID, Purpose: r.req.Purpose}), 4*time.Second)
		_, e := s.Stop(bound, r.p, r.req.RecordingID)
		cancel()
		if e != nil {
			failures = append(failures, e)
		}
	}
	return errors.Join(failures...)
}

func recordingOwner(ctx context.Context, p auth.Principal, clientID, sessionID string) error {
	actual, err := auth.FromContext(ctx)
	binding, bound := auth.ConsentBindingFromContext(ctx)
	if err != nil || !bound || clientID == "" || sessionID == "" || actual.Namespace != p.Namespace || actual.ClientID != clientID || p.ClientID != clientID || binding.SessionID != sessionID {
		return auth.ErrUnauthorized
	}
	return nil
}
