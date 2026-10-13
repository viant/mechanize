package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	create "github.com/viant/mechanize/data/chromeattemptbindingcreate"
	get "github.com/viant/mechanize/data/chromeattemptbindingget"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/xdatly/handler"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Inert actual Datly durable plan/intent/binding/outcome fixture, using the
// existing linked writers and readback contract. It supplies no Chrome input.
type reconnectDatlyFixture struct {
	builder    *durable.Builder
	runtime    *integration.Runtime
	setExecute func(integration.Execute)
	ctx        context.Context
	p          auth.Principal
	scope      ReconnectBindingScope
	descriptor BoundMutation
	read       func() []byte
	dispatches *atomic.Int32
}

func newReconnectDatlyFixture(t *testing.T, missing bool, completed ...bool) *reconnectDatlyFixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	p, e := auth.NewPrincipal("fixture", "", "joined-reconnect", []string{"desktop:control"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "original-tool-client"
	ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 60*time.Second)
	t.Cleanup(cancel)
	var b *durable.Builder
	var descriptor BoundMutation
	var commitErr error
	var dispatches atomic.Int32
	var next integration.Execute
	b, e = durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, PrepareStepAuthority: func(ctx context.Context, p auth.Principal, _ model.Step) (context.Context, int, error) {
		scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
		return scoped, 1, e
	}}, func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (integration.StepResult, error) {
		if next != nil {
			return next(ctx, p, step, values)
		}
		dispatches.Add(1)
		intent, e := data.RequireCommittedStepIntent(ctx, p)
		if e != nil {
			return integration.StepResult{}, e
		}
		pinned := ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, BrokerEpoch: "broker1", ChannelEpoch: "channel1", ScopeHash: strings.Repeat("a", 64), Lease: Lease{ID: "lease-private", Generation: 1}}
		pinned.Document.Identity = Identity{ProfileChannel: "p1", BrowserInstance: "b1", TabID: 7, DocumentID: "d1", Generation: 1}
		id := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
		command := Command{Action: step.Action, Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: &pinned.Lease, AttemptID: id, Locator: &Locator{Strategy: "id", Value: "save", Exact: true}}
		fingerprint, e := FingerprintMutationV2(command)
		if e != nil {
			return integration.StepResult{}, e
		}
		descriptor = BoundMutation{Action: step.Action, BrowserAttemptID: id, Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: pinned.Lease, Fingerprint: fingerprint}
		_, commitErr = commitReconnectDatlyBinding(ctx, p, step, pinned, descriptor, b.InvokeCommittedComponent)
		if commitErr != nil {
			return integration.StepResult{}, commitErr
		}
		if missing {
			panic("fixture process loss before original outcome")
		}
		// The only executor is this inert fixture; recovery must never invoke it again.
		result := integration.StepResult{DispatchState: "unknown", VerificationState: "unknown", Value: &model.Value{Kind: model.StringValue, String: "FIXTURE-PRIVATE-RESULT-CANARY"}}
		if len(completed) == 1 && completed[0] {
			return result, nil
		}
		return result, errors.New("fixture executor cleanup unconfirmed")
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close(context.Background()) })
	execute := func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (result integration.StepResult, err error) {
		defer func() {
			if recover() != nil {
				err = errors.New("fixture stopped before outcome")
			}
		}()
		return b.Execute(ctx, p, step, values)
	}
	runtimeService, e := integration.NewWithOptions(execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, id string, revision int, session, operation string) error {
		_, e := b.AttachOperation(ctx, p, id, revision, session, operation)
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := runtimeService.Open(ctx, "joined reconnect fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { runtimeService.Close(ctx, session.SessionID) })
	plan, e := script.Compile(`web.tab(origin:"https://fixture.example.test").getById("save",exact:true).click()`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixture": {Kind: model.StringValue, String: "joined-reconnect"}}
	operation, e := runtimeService.StartPlan(ctx, session.SessionID, *plan, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runtimeService.Wait(ctx, session.SessionID, operation.ID); e != nil {
		t.Fatal(e)
	}
	if commitErr != nil || dispatches.Load() != 1 || descriptor.BrowserAttemptID == "" {
		t.Fatal("actual durable binding fixture failed", commitErr)
	}
	scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	server, e := datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { server.Shutdown(context.Background()) })
	read := func() []byte {
		in := &get.LoadChromeAttemptBindingInput{}
		in.SetNamespace(p.Namespace)
		in.SetClientID(p.ClientID)
		in.SetBrowserAttemptID(descriptor.BrowserAttemptID)
		value, e := server.InvokeComponent(scoped, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeattemptbindingget", Name: "LoadChromeAttemptBinding"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeattemptbindingget"}}, Input: in})
		if e != nil {
			t.Fatal(e)
		}
		out := value.(*get.LoadChromeAttemptBindingOutput)
		if len(out.Data) != 1 {
			t.Fatal("original binding disappeared")
		}
		raw, _ := json.Marshal(out.Data[0])
		return raw
	}
	current := p
	current.ClientID = "current-native-client"
	return &reconnectDatlyFixture{builder: b, runtime: runtimeService, setExecute: func(execute integration.Execute) { next = execute }, ctx: auth.WithPrincipal(ctx, current), p: current, scope: ReconnectBindingScope{ProfileChannel: "p1", BrowserInstance: "b1", ScopeHash: strings.Repeat("a", 64), PendingDigest: strings.Repeat("b", 64)}, descriptor: descriptor, read: read, dispatches: &dispatches}
}

type reconnectCommittedInvoker func(context.Context, auth.Principal, exec.ComponentRequest) (any, error)

// commitReconnectDatlyBinding persists only identities/digests, never resolved page input.
// The caller is the once-only broker gate, before any transport write.
func commitReconnectDatlyBinding(ctx context.Context, p auth.Principal, step model.Step, pinned ControlAuthority, d BoundMutation, invoke reconnectCommittedInvoker) (BindingCommit, error) {
	fail := func() (BindingCommit, error) {
		return BindingCommit{}, errors.New("Chrome committed binding could not be qualified")
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
	row, err := reconnectDatlyBindingRow(a)
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
	if !ok || out == nil || len(out.Data) != 1 || out.Data[0] == nil || !reconnectDatlyBindingMatches(a, out.Data[0]) {
		return fail()
	}
	if _, err = data.RequireCommittedStepIntent(bound, p); err != nil {
		return fail()
	}
	return BindingCommit{BindingID: a.ID, CommitConfirmed: true, ReadbackMatched: true}, nil
}

func reconnectDatlyBindingMatches(a data.ChromeAttemptBindingAuthority, row *get.Binding) bool {
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

func reconnectDatlyBindingRow(a data.ChromeAttemptBindingAuthority) (*create.Binding, error) {
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
