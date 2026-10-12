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

type tabActivationBackend interface {
	PrepareActivateTab(context.Context, auth.Principal, string, string) (context.Context, int, error)
	ExecuteActivateTab(context.Context, auth.Principal, string, string, string, func(context.Context) error) (automation.StepResult, error)
}
type activateTabAdmissionKey struct{}
type activateTabAdmission struct {
	namespace, client, origin, tabHandle string
	epoch                                int
}

var errActivateTab = errors.New("tracked browser tab activation unavailable")

func activateTabFailure(err error, state string) error {
	code := "tabActivationUnavailable"
	var diagnostic *model.MechanizeError
	if errors.As(err, &diagnostic) {
		code = model.TabActivationReason(diagnostic.Code)
	}
	return &model.MechanizeError{Code: code, Message: "Tracked browser tab activation unavailable", Stage: "browser", DispatchState: state}
}

func (h *Host) tabActivationBackend() tabActivationBackend {
	if h.activateTabFixture != nil {
		return h.activateTabFixture
	}
	if h.chrome == nil {
		return nil
	}
	return h.chrome
}
func (h *Host) activateTabActor(ctx context.Context, requested auth.Principal, step model.Step) (auth.Principal, error) {
	p, e := auth.FromContext(ctx)
	binding, ok := auth.ConsentBindingFromContext(ctx)
	if e != nil || requested.Validate() != nil || p.Namespace != requested.Namespace || p.ClientID != requested.ClientID || !p.HasScope("desktop:control") || auth.NativeHuman(ctx) || step.Action != "browser.activateTab" || step.Validate() != nil || !ok || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, binding.SessionID) != nil {
		return auth.Principal{}, auth.ErrUnauthorized
	}
	if _, e = h.authorize(ctx, p); e != nil {
		return auth.Principal{}, e
	}
	return p, nil
}
func (h *Host) prepareActivateTab(ctx context.Context, requested auth.Principal, step model.Step) (context.Context, int, error) {
	p, e := h.activateTabActor(ctx, requested, step)
	if e != nil {
		return nil, 0, activateTabFailure(e, "notDispatched")
	}
	backend := h.tabActivationBackend()
	if backend == nil {
		return nil, 0, activateTabFailure(e, "notDispatched")
	}
	// This checks real Control consent without taking a DOM/Vault exposure permit.
	// It authorizes only channel metadata here; dispatch reauthorizes below.
	lease, e := h.authorizeConsentOperation(ctx, p, step.Target.Surface, true, consent.Control)
	if e != nil {
		return nil, 0, activateTabFailure(e, "notDispatched")
	}
	binding, ok := auth.ConsentBindingFromContext(lease.Context)
	lease.Release()
	if !ok {
		return nil, 0, auth.ErrUnauthorized
	}
	bound := auth.WithConsentBinding(ctx, binding)
	pinned, epoch, e := backend.PrepareActivateTab(bound, p, step.Target.Surface.Origin, step.Target.Surface.TabID)
	if e != nil || pinned == nil || epoch <= 0 {
		return nil, 0, activateTabFailure(e, "notDispatched")
	}
	return context.WithValue(pinned, activateTabAdmissionKey{}, activateTabAdmission{namespace: p.Namespace, client: p.ClientID, origin: step.Target.Surface.Origin, tabHandle: step.Target.Surface.TabID, epoch: epoch}), epoch, nil
}
func (h *Host) executeActivateTab(ctx context.Context, requested auth.Principal, step model.Step) (automation.StepResult, error) {
	denied := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	p, e := h.activateTabActor(ctx, requested, step)
	if e != nil {
		return denied, activateTabFailure(e, "notDispatched")
	}
	backend := h.tabActivationBackend()
	pin, ok := ctx.Value(activateTabAdmissionKey{}).(activateTabAdmission)
	intent, e := data.RequireCommittedStepIntent(ctx, p)
	if backend == nil || !ok || e != nil || pin.namespace != p.Namespace || pin.client != p.ClientID || pin.origin != step.Target.Surface.Origin || pin.tabHandle != step.Target.Surface.TabID || pin.epoch != intent.LeaseEpoch || intent.StepID != step.ID {
		return denied, activateTabFailure(nil, "notDispatched")
	}
	lease, e := h.authorizeConsentOperation(ctx, p, step.Target.Surface, true, consent.Control)
	if e != nil {
		return denied, activateTabFailure(e, "notDispatched")
	}
	defer lease.Release()
	original, _ := auth.ConsentBindingFromContext(ctx)
	actual, _ := auth.ConsentBindingFromContext(lease.Context)
	if original != actual || actual.SessionID != intent.SessionID {
		return denied, activateTabFailure(nil, "notDispatched")
	}
	attempt := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
	admit := func(c context.Context) error {
		current, e := data.RequireCommittedStepIntent(c, p)
		if e != nil || current != intent || lease.Context.Err() != nil || h.Runtime.CheckSession(c, p, intent.SessionID) != nil {
			return errActivateTab
		}
		return c.Err()
	}
	out, e := backend.ExecuteActivateTab(lease.Context, p, pin.origin, pin.tabHandle, attempt, admit)
	result := automation.StepResult{DispatchState: out.DispatchState, VerificationState: "unknown"}
	if result.DispatchState != "notDispatched" && result.DispatchState != "dispatched" && result.DispatchState != "unknown" {
		result.DispatchState = "unknown"
	}
	if e != nil {
		return result, activateTabFailure(e, result.DispatchState)
	}
	if out.DispatchState != "dispatched" || out.VerificationState != "verified" || out.Value != nil {
		return result, activateTabFailure(e, result.DispatchState)
	}
	result.VerificationState = "verified"
	return result, nil
}

// BrowserActivateTab is a convenience wrapper around the normal immutable-plan,
// BeginAttempt, receipt and CommitOutcome path. It never calls Chrome directly.
func (h *Host) BrowserActivateTab(ctx context.Context, p auth.Principal, in gateway.BrowserActivateTabInput) (gateway.BrowserActivateTabResult, error) {
	out := gateway.BrowserActivateTabResult{Outcome: "unknown", Reason: "tabActivationPending"}
	actual, e := auth.FromContext(ctx)
	if e != nil || p.Validate() != nil || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID || h.Runtime == nil || h.Runtime.CheckSession(ctx, p, in.SessionID) != nil || len(in.ClientRequestID) < 1 || len(in.ClientRequestID) > 128 || !model.ExactHTTPOrigin(in.Origin) || !model.OpaqueTabHandle(in.TabHandle) {
		return out, auth.ErrUnauthorized
	}
	p = actual
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: in.SessionID, Purpose: "Activate approved existing browser tab"})
	surface := model.Surface{Kind: "web", Origin: in.Origin, TabID: in.TabHandle}
	consentLease, e := h.authorizeConsentOperation(ctx, p, surface, true, consent.Control)
	if e != nil {
		return out, e
	}
	binding, _ := auth.ConsentBindingFromContext(consentLease.Context)
	consentLease.Release()
	ctx = auth.WithConsentBinding(ctx, binding)
	step := model.Step{ID: "activate-tab", Action: "browser.activateTab", Target: model.Selector{Surface: surface, Cardinality: "one"}, TimeoutMs: 3000, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"origin": {Kind: model.StringValue, String: in.Origin}, "tab": {Kind: model.StringValue, String: in.TabHandle}, "request": {Kind: model.StringValue, String: in.ClientRequestID}}}}
	plan := model.Plan{SchemaVersion: 1, Name: "Activate approved existing tab", Steps: []model.Step{step}}
	if e = plan.Validate(); e != nil {
		return out, errActivateTab
	}
	op, e := h.Runtime.StartPlanWithRequest(ctx, in.SessionID, in.ClientRequestID, plan, nil)
	if e != nil {
		return out, errActivateTab
	}
	out.OperationID = op.ID
	out.RunID, _ = h.Runtime.RunReference(ctx, in.SessionID, op.ID)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	finished, e := h.Runtime.Wait(bounded, in.SessionID, op.ID)
	if status, statusErr := h.Runtime.TabActivationOutcome(ctx, in.SessionID, op.ID); statusErr == nil {
		out.Reason = status.Reason
		if status.DispatchState == "unknown" && status.Reason == "tabActivationPending" {
			out.Outcome = "pending"
		}
		if status.DispatchState == "notDispatched" {
			out.Outcome = "notDispatched"
		}
	}

	if e != nil || finished == nil || finished.Status != manager.OperationSucceeded {
		if out.Reason == "none" {
			out.Reason = "tabActivationPending"
		}
		return out, nil
	}
	out.Outcome = "activated"
	out.Reason = "none"
	return out, nil
}
