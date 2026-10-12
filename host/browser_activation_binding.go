package host

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	create "github.com/viant/mechanize/data/browseractivationbindingcreate"
	get "github.com/viant/mechanize/data/browseractivationbindingget"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/model"
	"github.com/viant/xdatly/handler"
)

// commitActivationBinding is called by the broker after signed admission, before
// its first transport write. Only confirmed insertion plus exact readback passes.
func commitActivationBinding(ctx context.Context, p auth.Principal, step model.Step, d chrome.ActivationBinding, invoke committedComponentInvoker) error {
	fail := func() error { return errors.New("browser activation binding unavailable") }
	intent, e := data.RequireCommittedStepIntent(ctx, p)
	handle := (chrome.Document{Identity: chrome.Identity{ProfileChannel: d.ProfileChannel, BrowserInstance: d.BrowserInstance, TabID: d.TabID}}).QualifiedTabID()
	if e != nil || invoke == nil || step.Validate() != nil || step.Action != "browser.activateTab" || step.ID != intent.StepID || d.Namespace != p.Namespace || d.ClientID != p.ClientID || d.Origin != step.Target.Surface.Origin || handle != step.Target.Surface.TabID || d.BrowserAttemptID != data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID) || d.FingerprintVersion != 1 {
		return fail()
	}
	call := func(c context.Context, pkg, name, method string, in any, completion func(handler.Outcome)) (any, error) {
		return invoke(c, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: in, Completion: completion})
	}
	pi := &loadplan.LoadPlanInput{}
	pi.SetNamespace(p.Namespace)
	pi.SetPlanID(intent.PlanID)
	value, e := call(ctx, "loadplan", "LoadPlan", "GET", pi, nil)
	if e != nil {
		return fail()
	}
	plan, ok := value.(*loadplan.LoadPlanOutput)
	if !ok || plan == nil || len(plan.Data) != 1 || plan.Data[0] == nil || plan.Data[0].ContentHash == nil {
		return fail()
	}
	ri := &loadrun.LoadRunInput{}
	ri.SetNamespace(p.Namespace)
	ri.SetRunID(intent.RunID)
	value, e = call(ctx, "loadrun", "LoadRun", "GET", ri, nil)
	if e != nil {
		return fail()
	}
	run, ok := value.(*loadrun.LoadRunOutput)
	if !ok || run == nil || len(run.Data) != 1 || run.Data[0] == nil {
		return fail()
	}
	var effect *loadrun.Effect
	for _, candidate := range run.Data[0].Effects {
		if candidate != nil && candidate.Id != nil && *candidate.Id == intent.EffectID {
			if effect != nil {
				return fail()
			}
			effect = candidate
		}
	}
	if effect == nil || effect.BusinessKey == nil || effect.AttemptId == nil || *effect.AttemptId != intent.AttemptID || effect.State == nil || *effect.State != "intent" || effect.Revision == nil || *effect.Revision != 1 {
		return fail()
	}
	a := data.BrowserActivationBindingAuthority{Namespace: p.Namespace, ID: data.BrowserActivationBindingID(p.Namespace, p.ClientID, intent.AttemptID), ClientID: p.ClientID, Action: step.Action, RunID: intent.RunID, PlanID: intent.PlanID, StepID: intent.StepID, StepIndex: intent.StepIndex, DurableAttemptID: intent.AttemptID, EffectID: intent.EffectID, BrowserAttemptID: d.BrowserAttemptID, ProfileChannel: d.ProfileChannel, BrowserInstance: d.BrowserInstance, Origin: d.Origin, TabID: d.TabID, ChromePID: d.ChromePID, ChromeStartToken: d.ChromeStartToken, NativeHostPID: d.NativeHostPID, NativeHostStartToken: d.NativeHostStartToken, BrokerEpoch: d.BrokerEpoch, ChannelEpoch: d.ChannelEpoch, ScopeHash: d.ScopeHash, ChannelOperationEpoch: intent.LeaseEpoch, FingerprintVersion: d.FingerprintVersion, FingerprintDigest: d.FingerprintSHA256, PlanContentDigest: *plan.Data[0].ContentHash, StepDigest: data.ChromeRetirementDigest(step), BusinessKey: *effect.BusinessKey, BusinessKeyDigest: data.ChromeAttemptRawDigest(*effect.BusinessKey), CommittedRunRevision: intent.RunRevision, EndlySessionID: intent.SessionID, EndlyOperationID: intent.OperationID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	sealed, e := data.WithBrowserActivationBindingAuthority(ctx, a)
	if e != nil {
		return fail()
	}
	row, e := activationBindingRow(a)
	if e != nil {
		return fail()
	}
	in := &create.CreateBrowserActivationBindingInput{}
	in.SetNamespace(a.Namespace)
	in.SetClientID(a.ClientID)
	in.SetAttemptID(a.DurableAttemptID)
	in.SetEffectID(a.EffectID)
	in.SetRunID(a.RunID)
	in.SetPlanID(a.PlanID)
	in.SetCreateBrowserActivationBinding([]*create.Binding{row})
	var committed handler.Outcome
	if _, e = call(sealed, "browseractivationbindingcreate", "CreateBrowserActivationBinding", "POST", in, func(o handler.Outcome) { committed = o }); e != nil || !committed.CommitConfirmed() {
		return fail()
	}
	read := &get.LoadBrowserActivationBindingInput{}
	read.SetNamespace(a.Namespace)
	read.SetClientID(a.ClientID)
	read.SetBrowserAttemptID(a.BrowserAttemptID)
	value, e = call(sealed, "browseractivationbindingget", "LoadBrowserActivationBinding", "GET", read, nil)
	if e != nil {
		return fail()
	}
	out, ok := value.(*get.LoadBrowserActivationBindingOutput)
	if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil {
		return fail()
	}
	raw, e := json.Marshal(out.Data[0])
	var actual data.BrowserActivationBindingAuthority
	if e != nil || json.Unmarshal(raw, &actual) != nil || actual != a {
		return fail()
	}
	if _, e = data.RequireCommittedStepIntent(sealed, p); e != nil {
		return fail()
	}
	return nil
}

func activationBindingRow(a data.BrowserActivationBindingAuthority) (*create.Binding, error) {
	raw, e := json.Marshal(a)
	if e != nil {
		return nil, e
	}
	row := &create.Binding{}
	if e = json.Unmarshal(raw, row); e != nil {
		return nil, e
	}
	row.Has = &create.BindingHas{Namespace: true, Id: true, ClientId: true, Action: true, RunId: true, PlanId: true, StepId: true, StepIndex: true, DurableAttemptId: true, EffectId: true, BrowserAttemptId: true, ProfileChannel: true, BrowserInstance: true, Origin: true, TabId: true, ChromePid: true, ChromeStartToken: true, NativeHostPid: true, NativeHostStartToken: true, BrokerEpoch: true, ChannelEpoch: true, ScopeHash: true, ChannelOperationEpoch: true, FingerprintVersion: true, FingerprintDigest: true, PlanContentDigest: true, StepDigest: true, BusinessKey: true, BusinessKeyDigest: true, CommittedRunRevision: true, EndlySessionId: true, EndlyOperationId: true, CreatedAt: true}
	return row, nil
}
