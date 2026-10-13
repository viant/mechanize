package host

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	bindings "github.com/viant/mechanize/data/chromeattemptbindinglist"
	page "github.com/viant/mechanize/data/chromeattemptbindingpage"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

var errChromeReconnectHistory = errors.New("complete original reconnect history unavailable")

// This lifecycle callback retains the user admission lock through renderer
// proof/adoption. The Datly snapshot additionally owns its DB read transaction.
// It does not resolve business effects, release credential exposure or replay.
func (h *Host) chromeReconnectBindings(ctx context.Context, p auth.Principal, scope chrome.ReconnectBindingScope, check func(context.Context) error, consume func([]chrome.ReconnectBinding) error) error {
	if h == nil || h.durable == nil || check == nil || consume == nil || !retirementMatchHash.MatchString(scope.PendingDigest) {
		return errChromeReconnectHistory
	}
	return h.durable.WithChromeRetirementComponents(ctx, p, func(held context.Context, _ durable.RetirementComponentInvoker) error {
		if check(held) != nil {
			return errChromeReconnectHistory
		}
		bound, e := data.WithChromeReconnectBindingReadAuthority(held, data.ChromeReconnectBindingReadScope{ProfileChannel: scope.ProfileChannel, BrowserInstance: scope.BrowserInstance, ScopeHash: scope.ScopeHash}, check)
		if e != nil {
			return e
		}
		rows, e := h.durable.ChromeReconnectBindingSnapshot(bound, p)
		if e != nil {
			return e
		}
		receipts, e := projectChromeReconnectBindings(p, scope, rows)
		if e != nil {
			return e
		}
		if check(bound) != nil {
			return errChromeReconnectHistory
		}
		if e = consume(receipts); e != nil {
			return e
		}
		return check(bound)
	})
}

func projectChromeReconnectBindings(p auth.Principal, scope chrome.ReconnectBindingScope, rows []*page.Binding) ([]chrome.ReconnectBinding, error) {
	result := make([]chrome.ReconnectBinding, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		// Reuse the existing immutable binding validator without equating business
		// resolution with dispatch knowledge. Generated view types remain separate.
		encoded, e := json.Marshal(row)
		if e != nil || len(encoded) > 8<<20 {
			return nil, errChromeReconnectHistory
		}
		var b bindings.Binding
		var linked struct {
			Plan *loadplan.PlanRevision `json:"plan"`
		}
		if json.Unmarshal(encoded, &b) != nil || json.Unmarshal(encoded, &linked) != nil || b.ClientId == nil || b.BrokerEpoch == nil || b.ChannelEpoch == nil || b.ScopeHash == nil {
			return nil, errChromeReconnectHistory
		}
		originalActor := p
		originalActor.ClientID = *b.ClientId
		fence := ChromeRetirementFence{scope.ProfileChannel, scope.BrowserInstance, *b.BrokerEpoch, *b.ChannelEpoch, scope.ScopeHash}
		if !retirementBindingValid(originalActor, fence, &b) || seen[*b.BrowserAttemptId] || !reconnectPlanValid(p, &b, linked.Plan) {
			return nil, errChromeReconnectHistory
		}
		seen[*b.BrowserAttemptId] = true
		state, e := reconnectOriginalDispatch(p, &b)
		if e != nil {
			return nil, e
		}
		result = append(result, chrome.ReconnectBinding{Identity: chrome.Identity{ProfileChannel: scope.ProfileChannel, BrowserInstance: scope.BrowserInstance, TabID: *b.TabId, FrameID: *b.FrameId, DocumentID: *b.DocumentId, Generation: uint64(*b.DocumentGeneration)}, Fence: chrome.ReconnectFence{BrokerEpoch: *b.BrokerEpoch, ChannelEpoch: *b.ChannelEpoch, ScopeHash: *b.ScopeHash}, AttemptID: *b.BrowserAttemptId, Fingerprint: *b.FingerprintDigest, DispatchState: state, ControlLease: &chrome.Lease{ID: *b.RendererLeaseId, Generation: uint64(*b.RendererLeaseGeneration)}})
	}
	return result, nil
}
func reconnectPlanValid(p auth.Principal, b *bindings.Binding, plan *loadplan.PlanRevision) bool {
	if plan == nil || plan.Namespace == nil || *plan.Namespace != p.Namespace || plan.Id == nil || *plan.Id != *b.PlanId || plan.ContentHash == nil || *plan.ContentHash != *b.PlanContentDigest || plan.ContentJson == nil || len(*plan.ContentJson) > 4<<20 || data.ChromeAttemptRawDigest(*plan.ContentJson) != *plan.ContentHash {
		return false
	}
	var envelope struct {
		Plan model.Plan `json:"plan"`
	}
	if json.Unmarshal([]byte(*plan.ContentJson), &envelope) != nil || *b.StepIndex >= len(envelope.Plan.Steps) {
		return false
	}
	step := envelope.Plan.Steps[*b.StepIndex]
	if step.ID != *b.StepId || data.ChromeRetirementDigest(step) != *b.StepDigest {
		return false
	}
	count := 0
	for _, s := range envelope.Plan.Steps {
		if s.ID == step.ID {
			count++
		}
	}
	return count == 1
}
func reconnectOriginalDispatch(p auth.Principal, b *bindings.Binding) (string, error) {
	fail := func() (string, error) { return "", errChromeReconnectHistory }
	same := func(v *string, s string) bool { return v != nil && *v == s }
	a, e := b.Attempt, b.Effect
	if a == nil || e == nil || !same(a.Namespace, p.Namespace) || !same(a.Id, *b.DurableAttemptId) || !same(a.RunId, *b.RunId) || !same(a.PlanId, *b.PlanId) || !same(a.StepId, *b.StepId) || !same(a.State, "intent") || a.LeaseEpoch == nil || *a.LeaseEpoch != *b.RendererLeaseGeneration || !same(e.Namespace, p.Namespace) || !same(e.Id, *b.EffectId) || !same(e.AttemptId, *b.DurableAttemptId) || !same(e.RunId, *b.RunId) || e.BusinessKey == nil || len(*e.BusinessKey) > 65536 || data.ChromeAttemptRawDigest(*e.BusinessKey) != *b.BusinessKeyDigest || e.Revision == nil || *e.Revision < 1 || len(b.Outcomes) > 2 {
		return fail()
	}
	// A crash after the committed binding but before any outcome is not an
	// absence receipt. Preserve it as UNKNOWN; only the worker's independent
	// original-document absence proof can admit a fresh executor around it.
	if len(b.Outcomes) == 0 {
		if *e.Revision == 1 && same(e.State, "intent") && (e.EvidenceJson == nil || *e.EvidenceJson == "") {
			return "unknown", nil
		}
		return fail()
	}
	if *e.Revision < 2 {
		return fail()
	}
	var original *bindings.Outcome
	for _, o := range b.Outcomes {
		if o == nil || !same(o.Namespace, p.Namespace) || !same(o.RunId, *b.RunId) || !same(o.AttemptId, *b.DurableAttemptId) || o.Id == nil || o.Kind == nil || o.Sequence == nil || *o.Sequence < 1 || o.PayloadJson == nil || len(*o.PayloadJson) > 4<<20 {
			return fail()
		}
		if *o.Kind == "outcome" {
			if original != nil || *o.Id != data.ChromeRetirementDigest([]string{"outcome-event", *b.DurableAttemptId}) {
				return fail()
			}
			original = o
		} else if *o.Kind != "effect_reconciliation" {
			return fail()
		}
	}
	if original == nil {
		return fail()
	}
	var receipt integration.StepResult
	if json.Unmarshal([]byte(*original.PayloadJson), &receipt) != nil {
		return fail()
	}
	switch receipt.DispatchState {
	case "dispatched", "notDispatched", "unknown":
		return receipt.DispatchState, nil
	}
	return fail()
}
