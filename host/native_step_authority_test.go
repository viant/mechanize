package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/data/loadrun"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/objective"
	"github.com/viant/mechanize/session"
)

func TestNativeRecoveryFullOperationUsesPostProofIntentGenerationOnce(t *testing.T) {
	for _, order := range []string{"legacy-order", "proof-first", "cancel-before-intent", "human-revoke", "foreign-client", "stale-step", "held-input"} {
		t.Run(order, func(t *testing.T) {
			f := newControlFixture(t)
			f.principal.ClientID = "recovery-agent"
			f.principal.ClientName = "Recovery agent"
			f.principal.Scopes = append(f.principal.Scopes, "desktop:observe", "consent:admin")
			f.ctx = auth.WithPrincipal(context.Background(), f.principal)
			f.alive = false
			f.options.SemanticOnly = true
			f.ready.SemanticQualified = true
			f.ready.AllApplicationsQualified = true
			f.ready.QualifiedBundles = nil
			history := session.Lease{ID: "historical", Generation: 77, Owner: f.principal.Namespace, Scope: session.Scope{AllowedBundles: f.enrolled}}
			old, _ := json.Marshal(map[string]any{"generation": 77, "lease": history, "helper": f.identity, "inputProfile": "raw", "lastCleanup": session.CleanupReport{UnknownInputs: true, BusinessOutcomeUnknown: true}})
			if err := os.WriteFile(f.options.LockPath, old, 0600); err != nil {
				t.Fatal(err)
			}
			h := &Host{users: map[string]User{f.principal.Namespace: {DesktopAccess: true, NativeBundles: f.enrolled}}}
			helper := &hostDispatchHelper{controlFixture: f}
			transport := &fullPathNativeHelper{hostDispatchHelper: helper}
			f.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) {
				f.starts++
				f.alive = true
				f.identity.StartToken = fmt.Sprintf("new-helper-%d", f.starts)
				return transport, nil
			}
			if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.options.HelperPath}, HostOptions{NativeControl: &f.options}); err != nil {
				t.Fatal(err)
			}
			f.manager = h.nativeControl
			reader := &cleanupProofCaller{inventory: `{"complete":true,"apps":[{"bundleID":"com.google.Chrome"}]}`}
			h.nativeClient = reader
			if order == "held-input" {
				reader.inputHeld = true
			}
			_, file, _, _ := runtime.Caller(0)
			source, storage := filepath.Dir(filepath.Dir(file)), t.TempDir()
			evaluator, err := objective.New(map[string]objective.Enrollment{"fixture": {Adapter: &fullPathPredicate{host: h, helper: helper}, MaximumAuthority: objective.Observational, AllowedPredicates: map[string]bool{"saved": true}}})
			if err != nil {
				t.Fatal(err)
			}
			prepare := h.prepareStepExecutor
			if order == "cancel-before-intent" || order == "human-revoke" || order == "foreign-client" {
				prepare = func(ctx context.Context, p auth.Principal, step model.Step) (context.Context, int, error) {
					if order == "cancel-before-intent" {
						owned, cancel := context.WithCancel(ctx)
						prepared, epoch, err := h.prepareStepExecutor(owned, p, step)
						cancel()
						return prepared, epoch, err
					}
					prepared, epoch, err := h.prepareStepExecutor(ctx, p, step)
					if err != nil {
						return prepared, epoch, err
					}
					if order == "foreign-client" {
						foreign := p
						foreign.ClientID = "foreign-client"
						return auth.WithPrincipal(prepared, foreign), epoch, nil
					}
					binding, _ := auth.ConsentBindingFromContext(prepared)
					human, e := auth.WithNativeHuman(ctx)
					if e != nil {
						return prepared, epoch, e
					}
					request, _ := json.Marshal(map[string]any{"grantID": binding.GrantID})
					_, e = h.consent.NativeRPC(human, "revoke", request)
					return prepared, epoch, e
				}
			}
			if order == "legacy-order" {
				prepare = func(ctx context.Context, p auth.Principal, _ model.Step) (context.Context, int, error) {
					epoch, err := h.controlLeaseEpoch(ctx, p)
					return ctx, epoch, err
				}
			}
			dispatch := h.execute
			if order == "stale-step" {
				dispatch = func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
					changed := *step.Target.Locator
					changed.Value.String = "different-button"
					step.Target.Locator = &changed
					return h.execute(ctx, p, step, values)
				}
			}
			h.durable, err = durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: h.controlLeaseEpoch, PrepareStepAuthority: prepare, ObjectiveEvaluator: evaluator}, dispatch)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = h.Close(context.Background()) })
			h.Runtime, err = automation.NewWithOptions(h.durable.Execute, automation.Options{PreparePlan: h.durable.PreparePlan, EvaluatePostcondition: h.durable.EvaluatePostcondition, CompleteObjective: h.durable.CompleteObjective, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, revision int, session, operation string) error {
				_, err := h.durable.AttachOperation(ctx, p, run, revision, session, operation)
				return err
			}})
			if err != nil {
				t.Fatal(err)
			}
			opened, err := h.Runtime.Open(f.ctx, "Native recovery fixture")
			if err != nil {
				t.Fatal(err)
			}
			defer h.Runtime.Close(f.ctx, opened.SessionID)
			options := ConsentBrokerOptions{Invoke: h.durable.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: h.Runtime.CheckSession, Policy: h.ConsentPolicy, RecoverCleanup: h.proveConsentCleanup, RecoverNativeCleanup: h.proveNativeConsentCleanup}
			h.consent, err = NewConsentBroker(options)
			if err != nil {
				t.Fatal(err)
			}
			input := consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Control, consent.Observe}, Purpose: "Exact native recovery fixture", DurationSeconds: 120}
			request, err := h.consent.Request(f.ctx, f.principal, opened.SessionID, input)
			if err != nil {
				t.Fatal(err)
			}
			human, err := auth.WithNativeHuman(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
			value, err := h.consent.NativeRPC(human, "decide", decision)
			if err != nil {
				t.Fatal(err)
			}
			grant := value.(*consent.Grant)
			bound := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{GrantID: grant.ID, SessionID: opened.SessionID, Purpose: input.Purpose})
			oldLease, err := h.consent.Authorize(bound, f.principal, consent.Operation{GrantID: grant.ID, SessionID: opened.SessionID, Scope: consent.Scope{Kind: "application", BundleID: "com.fixture.app"}, Mode: consent.Control, Purpose: input.Purpose})
			if err != nil {
				t.Fatal(err)
			}
			internal, service, err := h.consent.bound(bound, f.principal)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = service.ReportDispatchCleanupUnknown(internal, grant.ID); err != nil {
				t.Fatal(err)
			}
			oldLease.Release()
			h.consent, err = NewConsentBroker(options)
			if err != nil {
				t.Fatal(err)
			}
			newSession := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: opened.SessionID, Purpose: input.Purpose})
			sawIntent := false
			transport.beforePress = func(ctx context.Context) error {
				intent, err := data.RequireCommittedStepIntent(ctx, f.principal)
				if err != nil {
					return err
				}
				if intent.LeaseEpoch <= 78 || h.nativeControl.held == nil || intent.LeaseEpoch != int(h.nativeControl.held.lease.Generation) {
					return errors.New("dispatch generation differs from post-proof committed intent")
				}
				q := &loadrun.LoadRunInput{}
				q.SetNamespace(f.principal.Namespace)
				q.SetRunID(intent.RunID)
				value, err := h.durable.InvokeCommittedComponent(ctx, f.principal, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/loadrun", Name: "LoadRun"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/loadrun"}}, Input: q})
				if err != nil {
					return err
				}
				rows := value.(*loadrun.LoadRunOutput).Data
				if len(rows) != 1 || len(rows[0].Attempts) != 1 || rows[0].Attempts[0].LeaseEpoch == nil || *rows[0].Attempts[0].LeaseEpoch != intent.LeaseEpoch || rows[0].Attempts[0].State == nil || *rows[0].Attempts[0].State != "intent" {
					return errors.New("actual immutable attempt did not store current helper generation before input")
				}
				sawIntent = true
				return nil
			}
			step := controlStep()
			step.TimeoutMs = 20000
			step.Effect.BusinessKey = map[string]model.Value{"operation": {Kind: model.StringValue, String: "native-recovery-save"}}
			step.Postcondition = &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{Target: &step.Target}, RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000}
			op, err := h.Runtime.StartPlan(newSession, opened.SessionID, model.Plan{SchemaVersion: 1, Requires: &model.Requirements{Adapters: []string{"fixture"}}, Steps: []model.Step{step}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			wait, cancel := context.WithTimeout(f.ctx, 45*time.Second)
			defer cancel()
			finished, err := h.Runtime.Wait(wait, opened.SessionID, op.ID)
			if err != nil {
				t.Fatal(err)
			}
			if order != "proof-first" {
				if finished.Status != manager.OperationFailed || helper.mutations != 0 || sawIntent {
					t.Fatal("invalid or canceled native authority was not refused before input", order)
				}
				return
			}
			if finished.Status != manager.OperationSucceeded || helper.mutations != 1 || !sawIntent || f.alive || f.starts != 2 {
				t.Fatalf("full native recovery result status=%v dispatches=%d intent=%v starts=%d alive=%v fixtureError=%s", finished.Status, helper.mutations, sawIntent, f.starts, f.alive, finished.Error)
			}
			internal, service, err = h.consent.bound(human, f.principal)
			if err != nil {
				t.Fatal(err)
			}
			grants, err := service.ListGrants(internal)
			if err != nil {
				t.Fatal(err)
			}
			if len(grants) != 1 || grants[0].RevocationState != consent.CleanupUnknown {
				t.Fatal("native recovery cleared suspended browser authority")
			}
		})
	}
}
