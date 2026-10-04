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
	create "github.com/viant/mechanize/data/chromeattemptbindingcreate"
	get "github.com/viant/mechanize/data/chromeattemptbindingget"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/model"
	"github.com/viant/xdatly/handler"
)

type committedComponentInvoker func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)

// commitChromeBinding persists only identities/digests, never resolved page input.
// The caller is the once-only broker gate, before any transport write.
func commitChromeBinding(ctx context.Context, p auth.Principal, step model.Step, pinned chrome.ControlAuthority, d chrome.BoundMutation, invoke committedComponentInvoker) (chrome.BindingCommit, error) {
	fail := func() (chrome.BindingCommit, error) {
		return chrome.BindingCommit{}, errors.New("Chrome committed binding could not be qualified")
	}
	intent, err := data.RequireCommittedStepIntent(ctx, p)
	if err != nil || invoke == nil || p.ClientID == "" || pinned.Owner != p.Namespace || pinned.ClientID != p.ClientID || step.ID != intent.StepID || d.Action != step.Action || d.Identity != pinned.Document.Identity || d.BrokerEpoch != pinned.BrokerEpoch || d.ChannelEpoch != pinned.ChannelEpoch || d.ScopeHash != pinned.ScopeHash || d.ControlLease != pinned.Lease || d.Fingerprint.Version != 2 || d.BrowserAttemptID != data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID) {
		return fail()
	}
	call := func(ctx context.Context, pkg, name, method string, in any, completion func(handler.Outcome)) (any, error) {
		return invoke(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: in, Completion: completion})
	}
	pi := &loadplan.LoadPlanInput{}
	pi.SetNamespace(p.Namespace)
	pi.SetPlanID(intent.PlanID)
	value, err := call(ctx, "loadplan", "LoadPlan", "GET", pi, nil)
	if err != nil {
		return fail()
	}
	po, ok := value.(*loadplan.LoadPlanOutput)
	if !ok || po == nil || len(po.Data) != 1 || po.Data[0] == nil || po.Data[0].ContentHash == nil {
		return fail()
	}
	ri := &loadrun.LoadRunInput{}
	ri.SetNamespace(p.Namespace)
	ri.SetRunID(intent.RunID)
	value, err = call(ctx, "loadrun", "LoadRun", "GET", ri, nil)
	if err != nil {
		return fail()
	}
	ro, ok := value.(*loadrun.LoadRunOutput)
	if !ok || ro == nil || len(ro.Data) != 1 || ro.Data[0] == nil {
		return fail()
	}
	var effect *loadrun.Effect
	for _, candidate := range ro.Data[0].Effects {
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
	a := data.ChromeAttemptBindingAuthority{
		Namespace: p.Namespace, ID: data.ChromeAttemptBindingID(p.Namespace, p.ClientID, intent.AttemptID), ClientID: p.ClientID,
		RunID: intent.RunID, PlanID: intent.PlanID, StepID: intent.StepID, StepIndex: intent.StepIndex, DurableAttemptID: intent.AttemptID, EffectID: intent.EffectID,
		BrowserAttemptID: d.BrowserAttemptID, ProfileChannel: d.Identity.ProfileChannel, BrowserInstance: d.Identity.BrowserInstance, BrokerEpoch: d.BrokerEpoch, ChannelEpoch: d.ChannelEpoch, ScopeHash: d.ScopeHash,
		TabID: d.Identity.TabID, FrameID: d.Identity.FrameID, DocumentID: d.Identity.DocumentID, DocumentGeneration: int64(d.Identity.Generation), RendererLeaseID: d.ControlLease.ID, RendererLeaseGeneration: int64(d.ControlLease.Generation),
		FingerprintVersion: d.Fingerprint.Version, FingerprintDigest: d.Fingerprint.SHA256, PlanContentDigest: *po.Data[0].ContentHash, StepDigest: data.ChromeRetirementDigest(step), BusinessKeyDigest: data.ChromeAttemptRawDigest(*effect.BusinessKey),
		CommittedRunRevision: intent.RunRevision, EndlySessionID: intent.SessionID, EndlyOperationID: intent.OperationID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), GuardProof: "committed-dispatch-bridge",
	}
	bound, err := data.WithChromeAttemptBindingAuthority(ctx, a)
	if err != nil {
		return fail()
	}
	row, err := chromeBindingRow(a)
	if err != nil {
		return fail()
	}
	in := &create.CreateChromeAttemptBindingInput{}
	in.SetNamespace(a.Namespace)
	in.SetClientID(a.ClientID)
	in.SetAttemptID(a.DurableAttemptID)
	in.SetEffectID(a.EffectID)
	in.SetRunID(a.RunID)
	in.SetPlanID(a.PlanID)
	in.SetCreateChromeAttemptBinding([]*create.Binding{row})
	var outcome handler.Outcome
	if _, err = call(bound, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", in, func(v handler.Outcome) { outcome = v }); err != nil || !outcome.CommitConfirmed() {
		return fail()
	}
	read := &get.LoadChromeAttemptBindingInput{}
	read.SetNamespace(a.Namespace)
	read.SetClientID(a.ClientID)
	read.SetBrowserAttemptID(a.BrowserAttemptID)
	value, err = call(bound, "chromeattemptbindingget", "LoadChromeAttemptBinding", "GET", read, nil)
	if err != nil {
		return fail()
	}
	out, ok := value.(*get.LoadChromeAttemptBindingOutput)
	if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil || !chromeBindingMatches(a, out.Data[0]) {
		return fail()
	}
	if _, err = data.RequireCommittedStepIntent(bound, p); err != nil {
		return fail()
	}
	return chrome.BindingCommit{BindingID: a.ID, CommitConfirmed: true, ReadbackMatched: true}, nil
}

func chromeBindingMatches(a data.ChromeAttemptBindingAuthority, row *get.Binding) bool {
	expected, err := json.Marshal(a)
	if err != nil {
		return false
	}
	actual, err := json.Marshal(row)
	if err != nil {
		return false
	}
	var e, r map[string]json.RawMessage
	if json.Unmarshal(expected, &e) != nil || json.Unmarshal(actual, &r) != nil {
		return false
	}
	for key, value := range e {
		if string(value) != string(r[key]) {
			return false
		}
	}
	return true
}

func chromeBindingRow(a data.ChromeAttemptBindingAuthority) (*create.Binding, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	row := &create.Binding{}
	if err = json.Unmarshal(raw, row); err != nil {
		return nil, err
	}
	// Presence markers are generated writer metadata and never caller input.
	row.Has = &create.BindingHas{Namespace: true, Id: true, ClientId: true, RunId: true, PlanId: true, StepId: true, StepIndex: true, DurableAttemptId: true, EffectId: true, BrowserAttemptId: true, ProfileChannel: true, BrowserInstance: true, BrokerEpoch: true, ChannelEpoch: true, ScopeHash: true, TabId: true, FrameId: true, DocumentId: true, DocumentGeneration: true, RendererLeaseId: true, RendererLeaseGeneration: true, FingerprintVersion: true, FingerprintDigest: true, PlanContentDigest: true, StepDigest: true, BusinessKeyDigest: true, CommittedRunRevision: true, EndlySessionId: true, EndlyOperationId: true, CreatedAt: true}
	return row, nil
}
