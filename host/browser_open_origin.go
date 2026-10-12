package host

import (
	"context"
	"errors"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
)

type originOpeningBackend interface {
	PrepareOpenOrigin(context.Context, auth.Principal, string) (context.Context, int, error)
	ExecuteOpenOrigin(context.Context, auth.Principal, string, string, func(context.Context) error) (automation.StepResult, error)
}
type openOriginAdmissionKey struct{}
type openOriginAdmission struct {
	namespace, client, origin string
	epoch                     int
}

var errOpenOrigin = errors.New("tracked browser origin opening unavailable")

func openOriginFailure(err error, state string) error {
	code := "openOriginUnavailable"
	var diagnostic *model.MechanizeError
	if errors.As(err, &diagnostic) {
		code = model.OpenOriginReason(diagnostic.Code)
	}
	return &model.MechanizeError{Code: code, Message: "Tracked browser origin opening unavailable", Stage: "browser", DispatchState: state}
}

func (h *Host) originOpeningBackend() originOpeningBackend {
	if h.openOriginFixture != nil {
		return h.openOriginFixture
	}
	if h.chrome == nil {
		return nil
	}
	return h.chrome
}
func (h *Host) openOriginActor(ctx context.Context, requested auth.Principal, step model.Step) (auth.Principal, error) {
	p, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || requested.Validate() != nil || p.Namespace != requested.Namespace || p.ClientID != requested.ClientID || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || step.Action != "browser.openOrigin" || step.Validate() != nil || !ok || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, binding.SessionID) != nil {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if _, e = h.authorize(ctx, p); e != nil {
		return auth.Principal{}, e
	}
	return p, nil
}
func (h *Host) prepareOpenOrigin(ctx context.Context, requested auth.Principal, step model.Step) (context.Context, int, error) {
	p, e := h.openOriginActor(ctx, requested, step)
	if e != nil {
		return nil, 0, openOriginFailure(e, "notDispatched")
	}
	backend := h.originOpeningBackend()
	if backend == nil {
		return nil, 0, openOriginFailure(e, "notDispatched")
	}
	// This checks real Control consent without taking a DOM/Vault exposure permit.
	// It authorizes only channel metadata here; dispatch reauthorizes below.
	lease, e := h.authorizeConsentOperation(ctx, p, step.Target.Surface, true, consent.Control)
	if e != nil {
		return nil, 0, openOriginFailure(e, "notDispatched")
	}
	binding, ok := auth.ConsentBindingFromContext(lease.Context)
	lease.Release()
	if !ok {
		return nil, 0, auth.ErrUnauthorized
	}
	bound := auth.WithConsentBinding(ctx, binding)
	pinned, epoch, e := backend.PrepareOpenOrigin(bound, p, step.Target.Surface.Origin)
	if e != nil || pinned == nil || epoch <= 0 {
		return nil, 0, openOriginFailure(e, "notDispatched")
	}
	return context.WithValue(pinned, openOriginAdmissionKey{}, openOriginAdmission{namespace: p.Namespace, client: p.ClientID, origin: step.Target.Surface.Origin, epoch: epoch}), epoch, nil
}
func (h *Host) executeOpenOrigin(ctx context.Context, requested auth.Principal, step model.Step) (automation.StepResult, error) {
	denied := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	p, e := h.openOriginActor(ctx, requested, step)
	if e != nil {
		return denied, openOriginFailure(e, "notDispatched")
	}
	backend := h.originOpeningBackend()
	pin, ok := ctx.Value(openOriginAdmissionKey{}).(openOriginAdmission)
	intent, e := data.RequireCommittedStepIntent(ctx, p)
	if backend == nil || !ok || e != nil || pin.namespace != p.Namespace || pin.client != p.ClientID || pin.origin != step.Target.Surface.Origin || pin.epoch != intent.LeaseEpoch || intent.StepID != step.ID {
		return denied, openOriginFailure(nil, "notDispatched")
	}
	lease, e := h.authorizeConsentOperation(ctx, p, step.Target.Surface, true, consent.Control)
	if e != nil {
		return denied, openOriginFailure(e, "notDispatched")
	}
	defer lease.Release()
	original, _ := auth.ConsentBindingFromContext(ctx)
	actual, _ := auth.ConsentBindingFromContext(lease.Context)
	if original != actual || actual.SessionID != intent.SessionID {
		return denied, openOriginFailure(nil, "notDispatched")
	}
	attempt := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
	admit := func(c context.Context) error {
		current, e := data.RequireCommittedStepIntent(c, p)
		if e != nil || current != intent || lease.Context.Err() != nil || h.Runtime.CheckSession(c, p, intent.SessionID) != nil {
			return errOpenOrigin
		}
		return c.Err()
	}
	out, e := backend.ExecuteOpenOrigin(lease.Context, p, pin.origin, attempt, admit)
	result := automation.StepResult{DispatchState: out.DispatchState, VerificationState: "unknown"}
	if result.DispatchState != "notDispatched" && result.DispatchState != "dispatched" && result.DispatchState != "unknown" {
		result.DispatchState = "unknown"
	}
	if e != nil {
		return result, openOriginFailure(e, result.DispatchState)
	}
	if out.DispatchState != "dispatched" || out.VerificationState != "verified" || out.Value == nil || out.Value.Validate() != nil || out.Value.Kind != model.StringValue || !model.OpaqueTabHandle(out.Value.String) {
		return result, openOriginFailure(e, result.DispatchState)
	}
	value := *out.Value
	result.Value = &value
	result.VerificationState = "verified"
	return result, nil
}

// BrowserOpenOrigin is a convenience wrapper around the normal immutable-plan,
// BeginAttempt, receipt and CommitOutcome path. It never calls Chrome directly.
func (h *Host) BrowserOpenOrigin(ctx context.Context, p auth.Principal, in gateway.BrowserOpenOriginInput) (gateway.BrowserOpenOriginResult, error) {
	out := gateway.BrowserOpenOriginResult{Outcome: "unknown", Reason: "openOriginPending"}
	actual, e := auth.FromContext(ctx)
	if e != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, in.SessionID) != nil || len(in.ClientRequestID) < 1 || len(in.ClientRequestID) > 128 || !model.ExactHTTPOrigin(in.Origin) {
		return out, auth.ErrUnauthorized
	}
	p = actual
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, Purpose: "Open approved website in a new background tab"})
	surface := model.Surface{Kind: "web", Origin: in.Origin}
	consentLease, e := h.authorizeConsentOperation(ctx, p, surface, true, consent.Control)
	if e != nil {
		return out, e
	}
	binding, _ := auth.ConsentBindingFromContext(consentLease.Context)
	consentLease.Release()
	ctx = auth.WithConsentBinding(ctx, binding)
	step := model.Step{ID: "open-origin", Action: "browser.openOrigin", Target: model.Selector{Surface: surface, Cardinality: "one"}, TimeoutMs: 3000, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"origin": {Kind: model.StringValue, String: in.Origin}, "request": {Kind: model.StringValue, String: in.ClientRequestID}}}, Bind: "createdTab", ResultType: model.StringValue}
	plan := model.Plan{SchemaVersion: 1, Name: "Open approved origin", Steps: []model.Step{step}}
	if e = plan.Validate(); e != nil {
		return out, errOpenOrigin
	}
	op, e := h.Runtime.StartPlanWithRequest(ctx, in.SessionID, in.ClientRequestID, plan, nil)
	if e != nil {
		return out, errOpenOrigin
	}
	out.OperationID = op.ID
	out.RunID, _ = h.Runtime.RunReference(ctx, in.SessionID, op.ID)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	finished, e := h.Runtime.Wait(bounded, in.SessionID, op.ID)
	if status, statusErr := h.Runtime.OriginOpeningOutcome(ctx, in.SessionID, op.ID); statusErr == nil {
		out.Reason = status.Reason
		if status.DispatchState == "unknown" && status.Reason == "openOriginPending" {
			out.Outcome = "pending"
		}
		if status.DispatchState == "notDispatched" {
			out.Outcome = "notDispatched"
		}
	}

	if e != nil || finished == nil || finished.Status != manager.OperationSucceeded {
		if out.Reason == "none" {
			out.Reason = "openOriginPending"
		}
		return out, nil
	}
	values, e := h.Runtime.OperationOutputs(ctx, in.SessionID, op.ID, []string{"createdTab"})
	out.Reason = "receiptUnavailable"
	if e != nil {
		return out, nil
	}
	value, ok := values.Outputs["createdTab"]
	if !ok || value.Kind != model.StringValue || !model.OpaqueTabHandle(value.String) {
		return out, nil
	}
	out.Outcome = "created"
	out.Reason = "none"
	out.TabHandle = value.String
	return out, nil
}
