package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Real manager preparation, durable admission, Endly and canonical controller;
// only the external renderer qualification is supplied. No page input occurs.
func TestWebPreparationFailureReachesOwnedControllerBeforeAnyIntent(t *testing.T) {
	for _, kind := range []string{"qualify", "cancelled", "unauthorized", "newLease", "changedCleanup", "admission", "readPin"} {
		t.Run(kind, func(t *testing.T) {
			f := newWebControlFixture(t)
			f.principal.ClientID = "controller:diagnostic"
			p := f.principal
			ctx := auth.WithPrincipal(context.Background(), p)
			var cause error = ErrWebControlUnqualified
			expectedStage, expectedCause := "qualify", "unavailable"
			switch kind {
			case "cancelled":
				cause = context.Canceled
				expectedCause = "cancelled"
			case "unauthorized":
				cause = auth.ErrUnauthorized
				expectedCause = "unauthorized"
			case "changedCleanup":
				cause = newWebPreparationCleanupFailure(&model.MechanizeError{Code: "staleAuthority", Message: "PRIVATE_CANARY original metadata change", DispatchState: "notDispatched"}, context.DeadlineExceeded)
				expectedCause = "leaseChanged"
			case "admission", "readPin":
				cause = newWebPreparationCleanupFailure(webPreparationAt(kind, errors.New("PRIVATE_CANARY original provider error")), context.DeadlineExceeded)
			case "newLease":
				cause = nil
				f.ready.NewlyAcquired = false
				expectedStage = "newLease"
				expectedCause = "intent"
			}
			originalQualify := f.manager.options.Qualify
			f.manager.options.Qualify = func(c context.Context, a auth.Principal, s model.Surface) (WebControlReadiness, error) {
				if cause != nil {
					return WebControlReadiness{}, errors.Join(cause, errors.New("PRIVATE_CANARY provider details"))
				}
				return originalQualify(c, a, s)
			}
			h := &Host{webControl: f.manager}
			source := filepath.Join(t.TempDir(), "no-source")
			storage := t.TempDir()
			var e error
			h.durable, e = durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, PrepareStepAuthority: h.prepareStepExecutor, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { t.Fatal("native lease acquired"); return 0, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
				t.Fatal("preparation failure dispatched")
				return integration.StepResult{}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer h.durable.Close(ctx)
			h.Runtime, e = integration.NewWithOptions(h.durable.Execute, integration.Options{PreparePlan: h.durable.PreparePlan, CompleteObjective: h.durable.CompleteObjective, AttachInitialOperation: func(c context.Context, a auth.Principal, id string, revision int, session, operation string) error {
				_, e := h.durable.AttachOperation(c, a, id, revision, session, operation)
				return e
			}})
			if e != nil {
				t.Fatal(e)
			}
			policy := script.Policy{AllowedSurfaces: map[string]bool{"https://fixture.test": true}, AllowMutation: true, Capabilities: map[string]bool{"web:semanticPress": true, "web:idLocator": true}}
			server, e := gateway.New(gateway.Dependencies{Runtime: h.Runtime, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return policy, nil }})
			if e != nil {
				t.Fatal(e)
			}
			controller, e := gateway.NewControllerDispatcher(server, h.Runtime)
			if e != nil {
				t.Fatal(e)
			}
			identity := chrome.ControllerIdentity{Principal: p, ConversationID: "fixture", Origin: "https://shell.fixture.test", DocumentID: "controller-document"}
			defer controller.CloseController(ctx, identity)
			call := func(name string, args any) map[string]any {
				t.Helper()
				raw, _ := json.Marshal(args)
				out, e := controller.CallTool(ctx, identity, chrome.ControllerToolCall{Name: name, Arguments: raw})
				if e != nil || out.IsError != nil && *out.IsError {
					t.Fatal("controller call", name, e, out)
				}
				raw, _ = json.Marshal(out.StructuredContent)
				if strings.Contains(string(raw), "PRIVATE_CANARY") {
					t.Fatal("provider text escaped")
				}
				var body map[string]any
				if e = json.Unmarshal(raw, &body); e != nil {
					t.Fatal(e)
				}
				return body
			}
			session := call("mechanize_session_open", map[string]any{"name": "fixture"})["sessionId"].(string)
			plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
			if e != nil {
				t.Fatal(e)
			}
			plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixture": {Kind: model.StringValue, String: "preparation"}}
			raw, _ := json.Marshal(plan)
			args := map[string]any{"sessionId": session, "clientRequestId": "original-request", "grantId": "fixture-grant", "purpose": "fixture", "source": string(raw), "format": "json"}
			started := call("mechanize_step_run", args)
			operation := started["operationId"].(string)
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if _, e = h.Runtime.Wait(bounded, session, operation); e != nil {
				t.Fatal(e)
			}
			status := call("mechanize_operation_status", map[string]any{"sessionId": session, "operationId": operation})
			failure, ok := status["executionFailure"].(map[string]any)
			if !ok || failure["code"] != "webPreparationUnavailable" || failure["dispatchState"] != "notDispatched" {
				t.Fatal("pre-intent diagnostic absent", status["executionFailure"])
			}
			detail := failure["preparation"].(map[string]any)
			expectedFields := 2
			if kind == "changedCleanup" || kind == "admission" || kind == "readPin" {
				expectedFields = 5
				if detail["cleanup"] != "unconfirmed" || detail["cleanupPhase"] != "retireWait" || detail["cleanupReason"] != "deadline" {
					t.Fatal("cleanup outcome not preserved", detail)
				}
			}
			if kind == "admission" || kind == "readPin" {
				expectedFields++
				if detail["substage"] != kind {
					t.Fatal("primary substage lost during cleanup", detail)
				}
			}
			if detail["stage"] != expectedStage || detail["cause"] != expectedCause || len(detail) != expectedFields {
				t.Fatal("finite phase/cause lost", detail)
			}
			if status["operationId"] != operation || status["sessionId"] != session || status["executionStatus"] != "failed" {
				t.Fatal("original operation identity lost")
			}
			again := call("mechanize_step_run", args)
			if again["operationId"] != operation {
				t.Fatal("original request replayed")
			}
			live, _ := h.Runtime.ExecutionFailure(ctx, session, operation)
			live.Preparation.Cause = "changed"
			current, _ := h.Runtime.ExecutionFailure(ctx, session, operation)
			if current.Preparation.Cause != expectedCause {
				t.Fatal("diagnostic aliased")
			}
			scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
			if e != nil {
				t.Fatal(e)
			}
			store, e := datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace})
			if e != nil {
				t.Fatal(e)
			}
			defer store.Shutdown(ctx)
			input := &loadrun.LoadRunInput{}
			input.SetNamespace(p.Namespace)
			input.SetRunID(status["runId"].(string))
			value, e := store.InvokeComponent(scoped, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/loadrun", Name: "LoadRun"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/loadrun"}}, Input: input})
			if e != nil {
				t.Fatal(e)
			}
			records := value.(*loadrun.LoadRunOutput)
			if len(records.Data) != 1 || len(records.Data[0].Attempts) != 0 || len(records.Data[0].Effects) != 0 {
				t.Fatal("preparation failure created input intent/effect")
			}
			foreign := p
			foreign.ClientID = "other"
			if _, e = h.Runtime.ExecutionFailure(auth.WithPrincipal(ctx, foreign), session, operation); !errors.Is(e, auth.ErrUnauthorized) {
				t.Fatal("foreign client obtained diagnostic")
			}
		})
	}
}

func TestPreparationDiagnosticKeepsPrimaryAndCleanupPrivateTextSeparate(t *testing.T) {
	primary := errors.New("PRIVATE_CANARY-primary")
	cleanup := errors.Join(context.DeadlineExceeded, errors.New("PRIVATE_CANARY-cleanup"))
	err := newWebPreparationCleanupFailure(webPreparationAt("admission", errors.Join(primary, ErrWebControlUnqualified)), cleanup)
	details := webPreparationDetails(err)
	captured := integration.CaptureStepPreparationFailure(integration.NewStepPreparationFailureDetail("qualify", webPreparationCause(err), webPreparationCleanupStatus(err), webPreparationSubstage(err), err, details))
	if captured == nil || captured.DispatchState != "notDispatched" || captured.Preparation.Cause != "unavailable" || captured.Preparation.Substage != "admission" || captured.Preparation.Cleanup != "unconfirmed" || captured.Preparation.CleanupPhase != "retireWait" || captured.Preparation.CleanupReason != "deadline" {
		t.Fatal("primary and cleanup diagnostics conflated")
	}
	raw, e := json.Marshal(captured)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "PRIVATE_CANARY") || !errors.Is(err, primary) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("private error leaked or original cause lost")
	}
}
