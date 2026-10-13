package durable

import (
	"context"
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/data/loadrun"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type diagnosticExecutorFailure struct{ *model.MechanizeError }

func (e diagnosticExecutorFailure) Unwrap() error { return e.MechanizeError }
func (e diagnosticExecutorFailure) PlaywrightExecutionDiagnostic() integration.PlaywrightDiagnostic {
	return integration.PlaywrightDiagnostic{Phase: e.Code, Callbacks: 12, PeerChecks: 2, PeerMs: 40, IdentityChecks: 18, ElapsedMs: 80, LastCallback: "relay.send", LastMethod: "Runtime.callFunctionOn"}
}

func TestRealDatlyPersistsClosedPlaywrightFailureWithoutReplayingRequest(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "diagnostic", []string{"desktop:control"})
	p.ClientID = "fixture-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	storage := t.TempDir()
	source := filepath.Join(t.TempDir(), "absent-source")
	calls := atomic.Int32{}
	var runID string
	failure := diagnosticExecutorFailure{&model.MechanizeError{Code: "playwrightDeadline", Stage: "browser", DispatchState: "notDispatched", EffectState: "none", Message: "PRIVATE_CANARY"}}
	builder, e := New(Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, PrepareStepAuthority: func(c context.Context, _ auth.Principal, _ model.Step) (context.Context, int, error) {
		return c, 1, nil
	}}, func(c context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		calls.Add(1)
		metadata, _ := integration.ExecutionFromContext(c)
		runID = metadata.RunID
		return integration.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, failure
	})
	if e != nil {
		t.Fatal(e)
	}
	defer builder.Close(ctx)
	runtime, e := integration.NewWithOptions(builder.Execute, integration.Options{PreparePlan: builder.PreparePlan, AttachInitialOperation: func(c context.Context, p auth.Principal, id string, revision int, session, operation string) error {
		_, e := builder.AttachOperation(c, p, id, revision, session, operation)
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := runtime.Open(ctx, "Diagnostic fixture")
	if e != nil {
		t.Fatal(e)
	}
	defer runtime.Close(ctx, session.SessionID)
	plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getByRole("button",name:"PRIVATE_SELECTOR",exact:true).click()`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixture": {Kind: model.StringValue, String: "diagnostic-case"}}
	op, e := runtime.StartPlanWithRequest(ctx, session.SessionID, "original-request", *plan, nil)
	if e != nil {
		t.Fatal(e)
	}
	wait, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, e = runtime.Wait(wait, session.SessionID, op.ID); e != nil {
		t.Fatal(e)
	}
	repeated, e := runtime.StartPlanWithRequest(ctx, session.SessionID, "original-request", *plan, nil)
	if e != nil || repeated.ID != op.ID || calls.Load() != 1 {
		t.Fatalf("original request identity/callback count changed: sameOperation=%v calls=%d error=%v", repeated.ID == op.ID, calls.Load(), e)
	}
	live, e := runtime.ExecutionFailure(ctx, session.SessionID, op.ID)
	if e != nil || live == nil || live.Playwright == nil || !live.Valid() {
		t.Fatal("live closed diagnostic absent", e)
	}
	live.Playwright.LastMethod = "mutated"
	again, _ := runtime.ExecutionFailure(ctx, session.SessionID, op.ID)
	if again.Playwright.LastMethod != "Runtime.callFunctionOn" {
		t.Fatal("live diagnostic was aliased")
	}
	scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	server, e := datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Shutdown(ctx)
	in := &loadrun.LoadRunInput{}
	in.SetNamespace(p.Namespace)
	in.SetRunID(runID)
	value, e := server.InvokeComponent(scoped, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/loadrun", Name: "LoadRun"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/loadrun"}}, Input: in})
	if e != nil {
		t.Fatal(e)
	}
	out := value.(*loadrun.LoadRunOutput)
	if len(out.Data) != 1 || len(out.Data[0].Effects) != 1 {
		t.Fatal("real persisted outcome missing")
	}
	effect := out.Data[0].Effects[0]
	if effect.State == nil || *effect.State != "absent" || effect.EvidenceJson == nil {
		t.Fatal("no-input receipt changed")
	}
	var saved integration.StepResult
	if json.Unmarshal([]byte(*effect.EvidenceJson), &saved) != nil || saved.ExecutionFailure == nil || saved.ExecutionFailure.Playwright == nil || saved.ExecutionFailure.Playwright.PeerMs != 40 || !saved.ExecutionFailure.Valid() {
		t.Fatal("durable typed phase/timing absent")
	}
	if strings.Contains(*effect.EvidenceJson, "PRIVATE") {
		t.Fatal("raw executor text entered diagnostic receipt")
	}
}
