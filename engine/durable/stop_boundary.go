package durable

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/data/stopboundary"
	"github.com/viant/mechanize/model"
	"github.com/viant/xdatly/handler"
)

type StopBoundaryRequest struct {
	RunID               string `json:"runId"`
	PlanID              string `json:"planId"`
	RequestID           string `json:"requestId"`
	ExpectedRunRevision int    `json:"expectedRunRevision"`
}
type StopBoundaryResult struct {
	CommitConfirmed bool                    `json:"commitConfirmed"`
	BoundaryID      string                  `json:"boundaryId,omitempty"`
	ResumeAdmitted  bool                    `json:"resumeAdmitted"`
	Reason          string                  `json:"reason,omitempty"`
	Run             *ReconciliationRunState `json:"run,omitempty"`
}

func validateStopPlan(run *loadrun.Run, req StopBoundaryRequest) error {
	if run == nil || run.Id == nil || *run.Id != req.RunID || run.PlanId == nil || *run.PlanId != req.PlanID || run.Plan == nil || run.Plan.ContentJson == nil || run.Plan.ContentHash == nil || data.ReconcileEffectHash([]byte(*run.Plan.ContentJson)) != *run.Plan.ContentHash {
		return ErrNeedsReconciliation
	}
	var envelope struct {
		Plan model.Plan `json:"plan"`
	}
	if json.Unmarshal([]byte(*run.Plan.ContentJson), &envelope) != nil || envelope.Plan.Validate() != nil {
		return ErrNeedsReconciliation
	}
	// The current host guard proves native executor quiescence only. A web or
	// mixed plan needs its own qualified executor guard before this is widened.
	for _, step := range envelope.Plan.Steps {
		if step.Target.Surface.Kind != "native" {
			return errors.New("stopped-boundary guard currently qualifies native plans only")
		}
	}
	return nil
}

func stoppedBoundaryReadback(run *loadrun.Run, req StopBoundaryRequest, auditID string) (bool, error) {
	var found *loadrun.Event
	for _, event := range run.Events {
		if event != nil && event.Id != nil && *event.Id == auditID {
			if found != nil {
				return false, ErrNeedsReconciliation
			}
			found = event
		}
	}
	if found == nil {
		return false, nil
	}
	if run.Revision == nil || *run.Revision <= req.ExpectedRunRevision || found.Kind == nil || *found.Kind != "stopped_boundary" || found.RunId == nil || *found.RunId != req.RunID || found.AttemptId != nil || found.PayloadJson == nil || run.EndlySessionId == nil || run.EndlyOperationId == nil {
		return false, ErrNeedsReconciliation
	}
	var recorded data.StopBoundaryAudit
	if json.Unmarshal([]byte(*found.PayloadJson), &recorded) != nil {
		return false, ErrNeedsReconciliation
	}
	expected := data.StopBoundaryAudit{PriorRunRevision: req.ExpectedRunRevision, RunID: req.RunID, PlanID: req.PlanID, RequestID: req.RequestID, EndlySessionID: *run.EndlySessionId, EndlyOperationID: *run.EndlyOperationId, QuiescenceProof: recorded.QuiescenceProof}
	if err := data.MatchStopBoundaryAudit(*found.PayloadJson, expected); err != nil {
		return false, err
	}
	return true, nil
}

// StopBoundary records an already-quiescent native run. It never cancels an
// active operation, clears unknown effects, replays input or admits resume.
// Cancel live operations through Endly before requesting this boundary.
func (b *Builder) StopBoundary(ctx context.Context, p auth.Principal, req StopBoundaryRequest) (result StopBoundaryResult, resultErr error) {
	for _, id := range []string{req.RunID, req.PlanID, req.RequestID} {
		if strings.TrimSpace(id) == "" || len(id) > 256 || strings.ContainsAny(id, "\r\n\x00") {
			return result, errors.New("bounded exact stopped-boundary references required")
		}
	}
	if req.ExpectedRunRevision < 1 {
		return result, errors.New("expected run revision required")
	}
	ctx, user, err := b.bound(ctx, p, 0)
	if err != nil {
		return result, err
	}
	if b.options.ReconciliationGuard == nil {
		return result, errors.New("qualified stopped executor guard unavailable")
	}
	release, err := b.options.ReconciliationGuard(ctx, p, req.RunID)
	if err != nil {
		return result, err
	}
	if release == nil {
		return result, errors.New("stopped executor guard unavailable")
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, err)
			result.Reason = "stopped-boundary guard cleanup unconfirmed"
			if result.Run != nil {
				result.Run.NeedsAttention = true
			}
		}
	}()
	user.mu.Lock()
	defer user.mu.Unlock()
	run, err := load(ctx, user.server, p, req.RunID)
	if err != nil {
		return result, err
	}
	if err = validateStopPlan(run, req); err != nil {
		return result, err
	}
	auditID := data.StopBoundaryAuditID(p.Namespace, req.RunID, req.RequestID)
	result.BoundaryID = auditID
	adopted, err := stoppedBoundaryReadback(run, req, auditID)
	if err != nil {
		return result, err
	}
	if adopted {
		result.CommitConfirmed = true
		state, e := stateRead(ctx, user.server, p, req.RunID)
		if e == nil {
			compact := reconciliationRunState(state)
			result.Run = &compact
		}
		return result, e
	}
	if run.Revision == nil || *run.Revision != req.ExpectedRunRevision || run.EndlySessionId == nil || run.EndlyOperationId == nil {
		return result, ErrNeedsReconciliation
	}
	sequence := 1
	for _, event := range run.Events {
		if event == nil || event.Sequence == nil {
			return result, ErrNeedsReconciliation
		}
		if *event.Sequence >= sequence {
			sequence = *event.Sequence + 1
		}
	}
	ctx, err = data.WithStateMutationPermit(ctx, p.Namespace, req.RunID)
	if err != nil {
		return result, err
	}
	at := now()
	a := data.StopBoundaryAuthority{Namespace: p.Namespace, RunID: req.RunID, PlanID: req.PlanID, RequestID: req.RequestID, EndlySessionID: *run.EndlySessionId, EndlyOperationID: *run.EndlyOperationId, RunRevision: req.ExpectedRunRevision, AuditSequence: sequence, Now: at, QuiescenceProof: "native-runtime-fence:" + key(req.RunID, req.PlanID, at, auditID)}
	ctx, err = data.WithStopBoundaryAuthority(ctx, a)
	if err != nil {
		return result, err
	}
	a, err = data.RequireStopBoundaryAuthority(ctx)
	if err != nil {
		return result, err
	}
	e := &stopboundary.Event{}
	e.SetNamespace(pointer(a.Namespace))
	e.SetId(pointer(a.AuditID))
	e.SetRunId(pointer(a.RunID))
	e.SetSequence(pointer(a.AuditSequence))
	e.SetKind(pointer("stopped_boundary"))
	e.SetPayloadJson(pointer(a.AuditPayloadJSON))
	e.SetCreatedAt(pointer(a.Now))
	r := &stopboundary.Run{}
	r.SetNamespace(pointer(a.Namespace))
	r.SetId(pointer(a.RunID))
	r.SetRevision(pointer(a.RunRevision))
	r.SetStatus(pointer("paused"))
	r.SetUpdatedAt(pointer(a.Now))
	r.SetEvents([]*stopboundary.Event{e})
	in := &stopboundary.StopBoundaryInput{}
	in.SetNamespace(a.Namespace)
	in.SetStopBoundary([]*stopboundary.Run{r})
	var outcome handler.Outcome
	_, err = user.server.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/stopboundary", Name: "StopBoundary"}, Route: spec.RouteRef{Method: "PATCH", Path: "/internal/data/stopboundary"}}, Input: in, Completion: func(v handler.Outcome) { outcome = v }})
	result.CommitConfirmed = outcome.CommitConfirmed()
	if err != nil {
		return result, err
	}
	if !result.CommitConfirmed {
		return result, errors.New("stopped-boundary commit unconfirmed; inspect same request ID")
	}
	state, err := stateRead(ctx, user.server, p, req.RunID)
	if err == nil {
		compact := reconciliationRunState(state)
		result.Run = &compact
	}
	if err != nil {
		result.Reason = "boundary committed; state readback unavailable"
	}
	return result, err
}
