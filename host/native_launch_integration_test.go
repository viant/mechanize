package host

import (
	"context"
	"encoding/json"
	"errors"
	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/objective"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/session"
)

func launchOnlyFixture(t *testing.T) (*Host, *controlFixture) {
	h, f := hostControlFixture(t)
	f.manager.options.LaunchOnly = true
	f.ready.Unlocked = false
	f.ready.Accessibility = false
	f.ready.EventPost = false
	f.ready.MutationQualified = false
	f.ready.LaunchQualified = true
	return h, f
}
func TestNativeLaunchOnlyRequiresLaunchEvidenceButNotInputPermissions(t *testing.T) {
	h, f := launchOnlyFixture(t)
	admission, err := h.admitNativeControl(f.ctx, f.principal)
	if err != nil || admission.Epoch <= 0 {
		t.Fatalf("launch-only admission %+v %v", admission, err)
	}
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || !policy.AllowMutation || !policy.Capabilities["native:appLaunch"] || policy.Capabilities["native:semanticPress"] || policy.Capabilities["native:attributeRead"] {
		t.Fatalf("launch expanded authority: %+v %v", policy, err)
	}
	plan, err := script.Compile(`app("com.fixture.app").open()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = (script.Validator{}).CheckPolicy(plan, policy); err != nil {
		t.Fatal(err)
	}
	f.ready.LaunchQualified = false
	if _, err = h.controlLeaseEpoch(f.ctx, f.principal); !errors.Is(err, ErrNativeControlUnqualified) {
		t.Fatalf("missing launch evidence admitted %v", err)
	}
}
func TestNativeLaunchOnlyCallerCannotDispatchAXOrInput(t *testing.T) {
	_, f := launchOnlyFixture(t)
	f.admit(t)
	caller := f.caller()
	for _, method := range []string{"elements.snapshot", "elements.read", "elements.press", "elements.setValue", "input.key", "input.text", "input.pointer"} {
		if _, err := caller.Call(f.ctx, native.Request{Method: method, Params: json.RawMessage(`{"expectedApp":"com.fixture.app","bundleID":"com.fixture.app"}`), Lease: &native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}}); !errors.Is(err, auth.ErrUnauthorized) {
			t.Fatalf("launch-only admitted %s: %v", method, err)
		}
	}
	if f.calls != 0 {
		t.Fatal("input-capable helper reached")
	}
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	for _, request := range []native.Request{
		{Method: "app.launch", Params: json.RawMessage(`{"expectedApp":"com.foreign.app"}`), Lease: &lease},
		{Method: "app.launch", Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`)},
	} {
		if _, err := caller.Call(f.ctx, request); err == nil {
			t.Fatal("scope/fence escape accepted")
		}
	}
	if _, err := caller.Call(f.ctx, native.Request{Method: "app.launch", Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`), Lease: &lease}); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Fatal("exact launch not dispatched once")
	}
}
func TestNativeQualificationReceivesHeldHelper(t *testing.T) {
	_, f := launchOnlyFixture(t)
	f.manager.options.Qualify = nil
	f.manager.options.QualifyHelper = func(ctx context.Context, p auth.Principal, identity session.ProcessIdentity, bundles []string, helper NativeControlHelper) (NativeControlReadiness, error) {
		if helper != f || identity != f.identity || p.Namespace != f.principal.Namespace || len(bundles) != 1 || bundles[0] != "com.fixture.app" {
			t.Fatal("qualification not bound to held helper")
		}
		ready := f.ready
		ready.ValidUntil = time.Now().Add(time.Second)
		return ready, nil
	}
	f.admit(t)
}
func TestNativeLaunchOnlyPolicyDoesNotAuthorizeReadingMail(t *testing.T) {
	h, f := launchOnlyFixture(t)
	step := controlStep()
	step.Action = "element.read"
	step.Effect.Class = model.ReadOnly
	step.Arguments = map[string]model.Value{"attribute": {Kind: model.StringValue, String: "name"}}
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil {
		t.Fatal(err)
	}
	if err = (script.Validator{}).CheckPolicy(&model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}, policy); err == nil {
		t.Fatal("launch scope manufactured AX reading access")
	}
}

type fullPathNativeHelper struct {
	*hostDispatchHelper
	beforePress func(context.Context) error
}

func (f *fullPathNativeHelper) Call(ctx context.Context, request native.Request) (native.Reply, error) {
	if request.Method == "doctor" {
		return native.Reply{HelperEpoch: "fixture", Result: json.RawMessage(`{"axTrusted":true,"semanticEnabled":true,"mutationEnabled":false,"launchEnabled":true}`)}, nil
	}
	if request.Method == "elements.press" && f.beforePress != nil {
		if err := f.beforePress(ctx); err != nil {
			return native.Reply{}, err
		}
	}
	return f.hostDispatchHelper.Call(ctx, request)
}

type fullPathPredicate struct {
	host   *Host
	helper *hostDispatchHelper
}

func (f *fullPathPredicate) Evaluate(ctx context.Context, p auth.Principal, name string, inputs map[string]model.Value) (objective.Result, error) {
	lease, err := f.host.AuthorizeOperation(ctx, p, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, false, consent.Observe)
	if err != nil {
		return objective.Result{}, err
	}
	defer lease.Release()
	if f.helper.mutations != 1 {
		return objective.Result{Truth: objective.False, Authority: objective.Observational, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "native", Reference: "fixture-state"}}}, nil
	}
	return objective.Result{Truth: objective.True, Authority: objective.Observational, ObservedAt: time.Now(), Evidence: []objective.Evidence{{Kind: "native", Reference: "fixture-state"}}}, nil
}

// The callback here is durable.Builder.Execute itself, not h.execute or a fake
// durable callback: consent's generated lookup re-enters the held admission lock.
func TestEndlyDurableConsentNativeFullExecutionPathDoesNotDeadlock(t *testing.T) {
	h, f := semanticFixture(t)
	f.principal.ClientID = "full-path-agent"
	f.principal.ClientName = "Full Path Agent"
	f.principal.Scopes = append(f.principal.Scopes, "consent:admin")
	f.ctx = auth.WithPrincipal(context.Background(), f.principal)
	helper := &hostDispatchHelper{controlFixture: f}
	nativeHelper := &fullPathNativeHelper{hostDispatchHelper: helper}
	f.manager.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) { return nativeHelper, nil }
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(file))
	storage := t.TempDir()
	evaluator, err := objective.New(map[string]objective.Enrollment{"fixture": {Adapter: &fullPathPredicate{host: h, helper: helper}, MaximumAuthority: objective.Observational, AllowedPredicates: map[string]bool{"saved": true}}})
	if err != nil {
		t.Fatal(err)
	}
	h.durable, err = durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: h.controlLeaseEpoch, ObjectiveEvaluator: evaluator}, h.execute)
	if err != nil {
		t.Fatal(err)
	}
	observer, err := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		return automation.StepResult{}, errors.New("observercannotdispatch")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close(context.Background())
	h.Runtime, err = automation.NewWithOptions(h.durable.Execute, automation.Options{PreparePlan: h.durable.PreparePlan, EvaluatePostcondition: h.durable.EvaluatePostcondition, CompleteObjective: h.durable.CompleteObjective, AttachInitialOperation: func(ctx context.Context, p auth.Principal, runID string, revision int, sessionID, operationID string) error {
		_, err := h.durable.AttachOperation(ctx, p, runID, revision, sessionID, operationID)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := h.Runtime.Open(f.ctx, "Full native fixture")
	if err != nil {
		t.Fatal(err)
	}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: h.durable.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: h.Runtime.CheckSession, Policy: h.ConsentPolicy})
	if err != nil {
		t.Fatal(err)
	}
	in := consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "com.fixture.app"}, Modes: []consent.Mode{consent.Control, consent.Observe}, Purpose: "Verify full execution path", DurationSeconds: 120}
	request, err := h.consent.Request(f.ctx, f.principal, session.SessionID, in)
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
	decided, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	bound := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: session.SessionID, GrantID: decided.(*consent.Grant).ID, Purpose: in.Purpose})
	sawIntent := false
	nativeHelper.beforePress = func(ctx context.Context) error {
		metadata, ok := automation.ExecutionFromContext(ctx)
		if !ok {
			return errors.New("durableexecutionmetadataabsent")
		}
		// A second read-only Datly host observes the committed intent independently;
		// no handwritten SQL or test hook into the primary held lock is used.
		state, err := observer.StateGet(auth.WithPrincipal(context.Background(), f.principal), f.principal, metadata.RunID)
		if err != nil {
			return err
		}
		if len(state.UnresolvedEffects) != 1 {
			return errors.New("committeddurableintentmissingbeforeinput")
		}
		sawIntent = true
		return nil
	}
	step := controlStep()
	// The independent generated read opens a second scoped Datly host at the
	// pre-dispatch boundary; give that fixture provisioning a bounded budget.
	step.TimeoutMs = 10000
	step.Effect.BusinessKey = map[string]model.Value{"operation": {Kind: model.StringValue, String: "fixture-save"}}
	step.Postcondition = &model.Predicate{Kind: "adapter", Adapter: "fixture", Name: "saved", Scope: model.PredicateScope{Target: &step.Target}, RequiredAuthority: "observational", TimeoutMs: 1000, FreshnessMs: 1000}
	operation, err := h.Runtime.StartPlan(bound, session.SessionID, model.Plan{SchemaVersion: 1, Requires: &model.Requirements{Adapters: []string{"fixture"}}, Steps: []model.Step{step}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	defer cancel()
	finished, err := h.Runtime.Wait(wait, session.SessionID, operation.ID)
	if err != nil {
		t.Fatalf("full Endly/intent/consent dispatch did not complete before deadline: %v", err)
	}
	defer h.Close(context.Background())
	defer h.Runtime.Close(f.ctx, session.SessionID)
	if finished.Status != manager.OperationSucceeded || helper.mutations != 1 || !sawIntent || f.alive {
		t.Fatalf("full path result %+v presses=%d intent=%v helperalive=%v", finished, helper.mutations, sawIntent, f.alive)
	}
	runID, err := h.Runtime.RunReference(f.ctx, session.SessionID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := h.durable.StateGet(f.ctx, f.principal, runID)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.UnresolvedEffects) != 0 || len(state.Progress) != 1 {
		t.Fatalf("effectoutcome not committed: %+v", state)
	}
}
