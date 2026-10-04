package chromeattemptbindingcreate_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	create "github.com/viant/mechanize/data/chromeattemptbindingcreate"
	get "github.com/viant/mechanize/data/chromeattemptbindingget"
	list "github.com/viant/mechanize/data/chromeattemptbindinglist"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/data/loadplan"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/xdatly/handler"
)

func markerSet(value any) {
	rv := reflect.ValueOf(value)
	v := rv.Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if v.Type().Field(i).Name == "Has" || f.Kind() == reflect.Pointer && f.IsNil() || f.Kind() == reflect.Slice && f.Len() == 0 {
			continue
		}
		m := rv.MethodByName("Set" + v.Type().Field(i).Name)
		if m.IsValid() {
			m.Call([]reflect.Value{f})
		}
	}
}
func TestGeneratedV2BindingReadsCommittedIntentBeforeInsertAndRetainsAbsentOutcome(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	p, _ := auth.NewPrincipal("fixture", "", "attempt-binding", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	s, err := datahost.Open(scoped, root, storage, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	invoke := func(ctx context.Context, pkg, name, method string, in any, completion func(handler.Outcome)) (any, error) {
		return s.InvokeComponent(ctx, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: in, Completion: completion})
	}
	var bound data.ChromeAttemptBindingAuthority
	var inserts atomic.Int32
	var callbackErr error
	var originalPlanJSON, originalBusinessJSON string
	var b *durable.Builder
	invokeCommitted := func(ctx context.Context, p auth.Principal, pkg, name, method string, in any, completion func(handler.Outcome)) (any, error) {
		return b.InvokeCommittedComponent(ctx, p, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + pkg, Name: name}, Route: spec.RouteRef{Method: method, Path: "/internal/data/" + pkg}}, Input: in, Completion: completion})
	}
	b, err = durable.New(durable.Options{SourceRoot: root, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, PrepareStepAuthority: func(ctx context.Context, p auth.Principal, _ model.Step) (context.Context, int, error) {
		ctx, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
		return ctx, 1, err
	}}, func(ctx context.Context, p auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		fail := func(err error) (integration.StepResult, error) {
			callbackErr = err
			return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, err
		}
		intent, err := data.RequireCommittedStepIntent(ctx, p)
		if err != nil {
			return fail(err)
		}
		planInput := &loadplan.LoadPlanInput{}
		planInput.SetNamespace(p.Namespace)
		planInput.SetPlanID(intent.PlanID)
		value, err := invokeCommitted(ctx, p, "loadplan", "LoadPlan", "GET", planInput, nil)
		if err != nil {
			return fail(err)
		}
		plan := value.(*loadplan.LoadPlanOutput).Data[0]
		runInput := &loadrun.LoadRunInput{}
		runInput.SetNamespace(p.Namespace)
		runInput.SetRunID(intent.RunID)
		value, err = invokeCommitted(ctx, p, "loadrun", "LoadRun", "GET", runInput, nil)
		if err != nil {
			return fail(err)
		}
		run := value.(*loadrun.LoadRunOutput).Data[0]
		if len(run.Effects) != 1 || run.Effects[0].BusinessKey == nil {
			return fail(fmt.Errorf("actual intent unavailable"))
		}
		originalPlanJSON, originalBusinessJSON = *plan.ContentJson, *run.Effects[0].BusinessKey
		bound = data.ChromeAttemptBindingAuthority{Namespace: p.Namespace, ClientID: p.ClientID, RunID: intent.RunID, PlanID: intent.PlanID, StepID: intent.StepID, StepIndex: intent.StepIndex, DurableAttemptID: intent.AttemptID, EffectID: intent.EffectID, ProfileChannel: "profile", BrowserInstance: "browser", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("a", 64), TabID: 7, DocumentID: "document", DocumentGeneration: 1, RendererLeaseID: "lease", RendererLeaseGeneration: int64(intent.LeaseEpoch), FingerprintVersion: 2, FingerprintDigest: strings.Repeat("b", 64), PlanContentDigest: *plan.ContentHash, StepDigest: data.ChromeRetirementDigest(step), BusinessKeyDigest: data.ChromeAttemptRawDigest(*run.Effects[0].BusinessKey), CommittedRunRevision: intent.RunRevision, EndlySessionID: intent.SessionID, EndlyOperationID: intent.OperationID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), GuardProof: "actual-held-dispatch"}
		bound.ID = data.ChromeAttemptBindingID(bound.Namespace, bound.ClientID, bound.DurableAttemptID)
		bound.BrowserAttemptID = data.ChromeAttemptBrowserIDV2(bound.Namespace, bound.ClientID, bound.DurableAttemptID)
		boundCtx, err := data.WithChromeAttemptBindingAuthority(ctx, bound)
		if err != nil {
			return fail(err)
		}
		payload, _ := json.Marshal(bound)
		var row create.Binding
		_ = json.Unmarshal(payload, &row)
		markerSet(&row)
		in := &create.CreateChromeAttemptBindingInput{}
		in.SetNamespace(bound.Namespace)
		in.SetClientID(bound.ClientID)
		in.SetAttemptID(bound.DurableAttemptID)
		in.SetEffectID(bound.EffectID)
		in.SetRunID(bound.RunID)
		in.SetPlanID(bound.PlanID)
		in.SetCreateChromeAttemptBinding([]*create.Binding{&row})
		// Rejections happen before the first successful insertion and cannot be
		// repaired by supplying matching body fields or a forged read relation.
		if inserts.Load() == 0 {
			if _, err := invokeCommitted(ctx, p, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", in, nil); err == nil {
				return fail(fmt.Errorf("binding accepted without sealed authority"))
			}
			in.SetClientID("other-client")
			if _, err := invokeCommitted(boundCtx, p, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", in, nil); err == nil {
				return fail(fmt.Errorf("binding accepted foreign input identity"))
			}
			in.SetClientID(bound.ClientID)
			row.SetFingerprintDigest(stringPointer(strings.Repeat("c", 64)))
			if _, err := invokeCommitted(boundCtx, p, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", in, nil); err == nil {
				return fail(fmt.Errorf("binding accepted altered fingerprint"))
			}
			row.SetFingerprintDigest(stringPointer(bound.FingerprintDigest))
		}
		var outcome handler.Outcome
		if _, err := invokeCommitted(boundCtx, p, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", in, func(v handler.Outcome) { outcome = v }); err != nil || !outcome.CommitConfirmed() {
			return fail(fmt.Errorf("binding commit %v %v", outcome.CommitConfirmed(), err))
		}
		inserts.Add(1)
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(ctx)
	r, err := integration.NewWithOptions(b.Execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, id string, revision int, session, operation string) error {
		_, err := b.AttachOperation(ctx, p, id, revision, session, operation)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := r.Open(ctx, "binding fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx, session.SessionID)
	plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
	if err != nil {
		t.Fatal(err)
	}
	plan.Steps[0].TimeoutMs = 120000
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: "case-1"}}
	wait, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	op, err := r.StartPlan(wait, session.SessionID, *plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Wait(wait, session.SessionID, op.ID); err != nil {
		t.Fatal(err)
	}
	if callbackErr != nil || inserts.Load() != 1 {
		t.Fatalf("native POST auxiliary hydration failed: inserts=%d err=%v", inserts.Load(), callbackErr)
	}
	getInput := &get.LoadChromeAttemptBindingInput{}
	getInput.SetNamespace(p.Namespace)
	getInput.SetClientID(p.ClientID)
	getInput.SetBrowserAttemptID(bound.BrowserAttemptID)
	value, err := invoke(scoped, "chromeattemptbindingget", "LoadChromeAttemptBinding", "GET", getInput, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := value.(*get.LoadChromeAttemptBindingOutput)
	if len(got.Data) != 1 || got.Data[0].Effect == nil || got.Data[0].Effect.State == nil || *got.Data[0].Effect.State != "absent" || len(got.Data[0].Outcomes) != 1 {
		t.Fatal("resolution reader lost actual immutable binding or absence outcome")
	}
	// Deliberately reconstruct the old host capability in this isolated fixture.
	// The live runtime revokes it on return; even this stale trusted assertion
	// cannot substitute for freshly loaded database facts after an outcome.
	oldIntent := data.CommittedStepIntent{Namespace: bound.Namespace, ClientID: bound.ClientID, RunID: bound.RunID, PlanID: bound.PlanID, StepID: bound.StepID, StepIndex: bound.StepIndex, AttemptID: bound.DurableAttemptID, EffectID: bound.EffectID, LeaseEpoch: int(bound.RendererLeaseGeneration), RunRevision: bound.CommittedRunRevision, SessionID: bound.EndlySessionID, OperationID: bound.EndlyOperationID}
	oldCtx, revoke, err := data.WithCommittedStepIntent(scoped, p, oldIntent)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	stale := bound
	stale.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	oldCtx, err = data.WithChromeAttemptBindingAuthority(oldCtx, stale)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(stale)
	var staleRow create.Binding
	_ = json.Unmarshal(payload, &staleRow)
	markerSet(&staleRow)
	staleInput := &create.CreateChromeAttemptBindingInput{}
	staleInput.SetNamespace(stale.Namespace)
	staleInput.SetClientID(stale.ClientID)
	staleInput.SetAttemptID(stale.DurableAttemptID)
	staleInput.SetEffectID(stale.EffectID)
	staleInput.SetRunID(stale.RunID)
	staleInput.SetPlanID(stale.PlanID)
	staleInput.SetCreateChromeAttemptBinding([]*create.Binding{&staleRow})
	if _, err := invoke(oldCtx, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", staleInput, nil); err == nil || !strings.Contains(err.Error(), "actual pristine committed effect intent differs") {
		t.Fatalf("changed database intent was not independently rejected: %v", err)
	}
	// A typed caller cannot turn the independent generated reads into body
	// assertions: these fully matching, stale pristine snapshots must be
	// replaced by current persisted facts on every invocation.
	staleInput.SetIntentRead([]*create.IntentReadRow{{Namespace: stringPointer(stale.Namespace), Id: stringPointer(stale.EffectID), AttemptId: stringPointer(stale.DurableAttemptID), RunId: stringPointer(stale.RunID), BusinessKey: stringPointer(originalBusinessJSON), State: stringPointer("intent"), Revision: intPointer(1)}})
	staleInput.SetAttemptRead([]*create.AttemptReadRow{{Namespace: stringPointer(stale.Namespace), Id: stringPointer(stale.DurableAttemptID), RunId: stringPointer(stale.RunID), PlanId: stringPointer(stale.PlanID), StepId: stringPointer(stale.StepID), State: stringPointer("intent"), LeaseEpoch: intPointer(int(stale.RendererLeaseGeneration))}})
	staleInput.SetRunRead([]*create.RunReadRow{{Namespace: stringPointer(stale.Namespace), Id: stringPointer(stale.RunID), PlanId: stringPointer(stale.PlanID), Status: stringPointer("running"), Revision: intPointer(stale.CommittedRunRevision), EndlySessionId: stringPointer(stale.EndlySessionID), EndlyOperationId: stringPointer(stale.EndlyOperationID)}})
	staleInput.SetPlanRead([]*create.PlanReadRow{{Namespace: stringPointer(stale.Namespace), Id: stringPointer(stale.PlanID), ContentHash: stringPointer(stale.PlanContentDigest), ContentJson: stringPointer(originalPlanJSON)}})
	staleInput.SetIntentEventRead([]*create.IntentEventRead{{Namespace: stringPointer(stale.Namespace), Id: stringPointer(data.ChromeRetirementDigest([]string{"intent-event", stale.DurableAttemptID})), RunId: stringPointer(stale.RunID), AttemptId: stringPointer(stale.DurableAttemptID), Kind: stringPointer("intent")}})
	if _, err := invoke(oldCtx, "chromeattemptbindingcreate", "CreateChromeAttemptBinding", "POST", staleInput, nil); err == nil || !strings.Contains(err.Error(), "actual pristine committed effect intent differs") {
		t.Fatalf("caller-provided pristine view snapshots substituted for database reads: %v", err)
	}
	listInput := &list.ListChromeAttemptBindingsInput{}
	listInput.SetNamespace(p.Namespace)
	listInput.SetClientID(p.ClientID)
	listInput.SetProfileChannel(bound.ProfileChannel)
	listInput.SetBrowserInstance(bound.BrowserInstance)
	listInput.SetBrokerEpoch(bound.BrokerEpoch)
	listInput.SetChannelEpoch(bound.ChannelEpoch)
	listInput.SetScopeHash(bound.ScopeHash)
	value, err = invoke(scoped, "chromeattemptbindinglist", "ListChromeAttemptBindings", "GET", listInput, nil)
	if err != nil || len(value.(*list.ListChromeAttemptBindingsOutput).Data) != 1 {
		t.Fatal("scoped exact-fence reader lost binding")
	}
	getInput.SetClientID("other-client")
	if _, err := invoke(scoped, "chromeattemptbindingget", "LoadChromeAttemptBinding", "GET", getInput, nil); err == nil {
		t.Fatal("cross-client binding read accepted")
	}
	// All rows are produced by actual BeginAttempt -> sealed POST -> generated
	// absent outcome operations. No fixture SQL or database writes bypass the
	// production components. The 65th matching row is an explicit overflow,
	// never a truncated set usable as retirement evidence.
	for i := 1; i < 65; i++ {
		op, err := r.StartPlan(wait, session.SessionID, *plan, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Wait(wait, session.SessionID, op.ID); err != nil {
			t.Fatal(err)
		}
		if callbackErr != nil || inserts.Load() != int32(i+1) {
			t.Fatalf("bounded row fixture %d: inserts=%d err=%v", i, inserts.Load(), callbackErr)
		}
	}
	value, err = invoke(scoped, "chromeattemptbindinglist", "ListChromeAttemptBindings", "GET", listInput, nil)
	if err == nil {
		t.Fatalf("65 matching bindings accepted as complete enumeration: %T", value)
	}
	if out, ok := value.(*list.ListChromeAttemptBindingsOutput); ok && len(out.Data) != 0 {
		t.Fatal("overflow returned partial retirement proof")
	}
}

func stringPointer(value string) *string { return &value }

func intPointer(value int) *int { return &value }
