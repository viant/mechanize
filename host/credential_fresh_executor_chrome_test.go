package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	manager "github.com/viant/endly/service/manager"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	sessionpkg "github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
)

type restartActivationFixture struct {
	t        *testing.T
	bridge   *protectionWorkerBridge
	identity chrome.Identity
	origin   string
	birth    sessionpkg.ProcessIdentity
	calls    int
}
type restartActivationPin struct{}

func (f *restartActivationFixture) PrepareActivateTab(ctx context.Context, p auth.Principal, origin, handle string) (context.Context, int, error) {
	actual, alive, e := sessionpkg.InspectProcess(f.birth.PID)
	if e != nil || !alive || actual != f.birth || origin != f.origin || handle != (chrome.Document{Identity: f.identity}).QualifiedTabID() {
		return nil, 0, auth.ErrUnauthorized
	}
	return context.WithValue(ctx, restartActivationPin{}, f), 77, nil
}
func (f *restartActivationFixture) ExecuteActivateTab(ctx context.Context, p auth.Principal, origin, handle, attempt string, admit func(context.Context) error) (automation.StepResult, error) {
	denied := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	intent, e := data.RequireCommittedStepIntent(ctx, p)
	if e != nil || ctx.Value(restartActivationPin{}) != f || admit == nil || admit(ctx) != nil || intent.LeaseEpoch != 77 || attempt != data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID) {
		return denied, auth.ErrUnauthorized
	}
	result, e := f.bridge.call(ctx, protectionWorkerRequest{Op: "activationUnknown", BrowserAttemptID: attempt, TargetIdentity: &f.identity})
	if e != nil || !result.ActivationUnknown || !result.ReceiptRetained || result.ActivationUpdates != 1 || result.ActivationFocus != 1 {
		return denied, errors.New("actual worker lost-ACK fixture unavailable")
	}
	f.calls++
	return automation.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("fixture dropped activation acknowledgement")
}

// Only the native helper transport is substituted. Admission, policy, consent,
// committed intent and cleanup execute through the production Host pipeline.
type restartNativeLaunchHelper struct {
	*hostDispatchHelper
	principal auth.Principal
	launch    func(context.Context) (sessionpkg.ProcessIdentity, error)
	launched  sessionpkg.ProcessIdentity
	sawIntent bool
}

func (f *restartNativeLaunchHelper) Call(ctx context.Context, request native.Request) (native.Reply, error) {
	switch request.Method {
	case "app.launch":
		intent, err := data.RequireCommittedStepIntent(ctx, f.principal)
		if err != nil || intent.AttemptID == "" {
			return native.Reply{}, errors.New("committed launch intent absent")
		}
		var params struct {
			ExpectedApp string `json:"expectedApp"`
		}
		if json.Unmarshal(request.Params, &params) != nil || params.ExpectedApp != "com.google.Chrome" || request.Lease == nil {
			return native.Reply{}, auth.ErrUnauthorized
		}
		f.sawIntent = true
		identity, err := f.launch(ctx)
		if err != nil {
			return native.Reply{}, err
		}
		f.launched = identity
		f.mutations++
		raw, _ := json.Marshal(map[string]any{"bundleID": "com.google.Chrome", "pid": identity.PID, "launchTime": identity.StartToken, "startToken": identity.StartToken, "active": false})
		return native.Reply{HelperEpoch: "fixture", Receipt: &native.Receipt{DispatchState: "dispatched"}, Result: raw}, nil
	case "apps.list":
		actual, alive, err := sessionpkg.InspectProcess(f.launched.PID)
		if err != nil || !alive || actual != f.launched {
			return native.Reply{}, errors.New("independent launched process observation failed")
		}
		raw, _ := json.Marshal(map[string]any{"complete": true, "apps": []map[string]any{{"bundleID": "com.google.Chrome", "pid": actual.PID, "launchTime": actual.StartToken, "startToken": actual.StartToken}}})
		return native.Reply{HelperEpoch: "fixture", Result: raw}, nil
	}
	return f.hostDispatchHelper.Call(ctx, request)
}

// Composite acceptance: Host, Datly, Vault, kernel process metadata, Endly and
// the production Chrome worker execute normally. The stdio browser transport and
// private admission/signature are fixture seams; signed native protocol is covered
// separately by backend/chrome's actual-Broker integration tests.
func TestCredentialFreshExecutorRetainsActivationUnknownAndAllowsNewPublicWorkflow(t *testing.T) {
	if os.Getenv("MECHANIZE_REAL_CHROME_SCOPES") != "1" {
		t.Skip("set MECHANIZE_REAL_CHROME_SCOPES=1 for disposable Chrome acceptance")
	}
	bridge := newProtectionWorkerBridge(t)
	bounded, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	initial, e := bridge.call(bounded, protectionWorkerRequest{Op: "init"})
	cancel()
	if e != nil {
		t.Fatal(e)
	}
	birth, alive, e := sessionpkg.InspectProcess(initial.ProcessPID)
	if e != nil || !alive || birth.UID != uint32(os.Getuid()) || !strings.Contains(birth.Executable, "Google Chrome") {
		t.Fatal("original disposable Chrome kernel identity unavailable", e)
	}
	current := initial
	currentBirth := birth
	retired := false
	var storeRoot string
	configure := func(f *credentialBrowserFixture) {
		f.admissionTransform = func(ctx context.Context, a chrome.ControlAuthority) (chrome.ControlAuthority, error) {
			a.Document.Identity = current.SourceIdentity
			if retired {
				a.Document.Identity = current.TargetIdentity
			}
			a.Evidence.ChromeParent = currentBirth
			a.BrokerEpoch = "fixture-broker"
			a.ChannelEpoch = "fixture-channel"
			a.ScopeHash = strings.Repeat("a", 64)
			return a, nil
		}
		f.scopeCapture = func(ctx context.Context, a chrome.ControlAuthority, id string) (chrome.CredentialProtectionScope, error) {
			s := chrome.CredentialProtectionScope{PreparationID: id, Identity: a.Document.Identity, Origin: a.Document.Origin, ChromeStartToken: a.Evidence.ChromeParent.StartToken, BrokerEpoch: a.BrokerEpoch, ChannelEpoch: a.ChannelEpoch, ScopeHash: a.ScopeHash}
			out, e := bridge.call(ctx, protectionWorkerRequest{Op: "capture", Scope: &s, ControlLease: &a.Lease})
			s.LoginRouteSHA256 = out.LoginRouteSHA256
			return s, e
		}
		f.scopeAbsent = func(ctx context.Context, s chrome.CredentialProtectionScope) error {
			if retired && s.ChromeStartToken == birth.StartToken {
				return sessionpkg.VerifyProcessBirthAbsent(ctx, birth.UID, birth.StartToken)
			}
			_, e := bridge.call(ctx, protectionWorkerRequest{Op: "absent", Scope: &s})
			return e
		}
		f.scopeRetire = func(ctx context.Context, s chrome.CredentialProtectionScope) error {
			if e := f.scopeAbsent(ctx, s); e != nil {
				return e
			}
			out, e := bridge.call(ctx, protectionWorkerRequest{Op: "retire", Scope: &s})
			if e == nil && !out.Retired {
				return errors.New("old worker protection record not retired")
			}
			return e
		}
		f.scopeDisjoint = func(ctx context.Context, s chrome.CredentialProtectionScope, target model.Surface) error {
			if target.TabID != (chrome.Document{Identity: current.PublicIdentity}).QualifiedTabID() {
				return errPrivateCredential
			}
			_, e := bridge.call(ctx, protectionWorkerRequest{Op: "disjoint", Scope: &s, TargetIdentity: &current.PublicIdentity})
			return e
		}
	}
	exercise := func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		if applied, e := h.CredentialApply(ctx, p, ref); e != nil || applied.State != "filled" {
			t.Fatal("original private fill fixture", e)
		}
		f.submitUnknown = true
		if submitted, e := h.CredentialSubmit(ctx, p, ref); e != nil || submitted.State != "unknown" {
			t.Fatal("original private unknown fixture", e)
		}
		oldPrivate := append([]data.CredentialDeliveryRecord(nil), f.session.attempts...)
		activation := &restartActivationFixture{t: t, bridge: bridge, identity: initial.SourceIdentity, origin: initial.Origin, birth: birth}
		h.activateTabFixture = activation
		request := gateway.BrowserActivateTabInput{SessionID: input.SessionID, ClientRequestID: "original-visibility", Origin: initial.Origin, TabHandle: (chrome.Document{Identity: initial.SourceIdentity}).QualifiedTabID()}
		unknown, e := h.BrowserActivateTab(ctx, p, request)
		if e != nil || unknown.Outcome != "unknown" || unknown.RunID == "" || activation.calls != 1 {
			t.Fatal("actual activation did not create durable UNKNOWN", unknown, e)
		}
		replay, e := h.BrowserActivateTab(ctx, p, request)
		if e != nil || replay.RunID != unknown.RunID || replay.OperationID != unknown.OperationID || activation.calls != 1 {
			t.Fatal("original request replayed activation", e)
		}
		oldState, e := h.durable.StateGet(ctx, p, unknown.RunID)
		if e != nil || len(oldState.UnresolvedEffects) != 1 {
			t.Fatal("original unresolved effect unavailable", e)
		}
		before, _ := json.Marshal(oldState)
		liveCheck, stopLiveCheck := context.WithTimeout(ctx, time.Second)
		liveAbsence := sessionpkg.VerifyProcessBirthAbsent(liveCheck, birth.UID, birth.StartToken)
		timedOut := liveCheck.Err() != nil
		stopLiveCheck()
		if liveAbsence == nil || timedOut {
			t.Fatal("live original Chrome birth did not fail absence proof immediately")
		}
		t.Log("kernel source proof: live original birth correctly refused")
		// The empty Go gateway is only a fixture transport sentinel, not a live
		// Broker. Close the actual Host/runtime/store without pretending it is one.
		h.chrome = nil
		if e = h.Close(context.Background()); e != nil {
			t.Fatal("original Host did not stop", e)
		}
		_, file, _, _ := runtime.Caller(0)
		sourceRoot := filepath.Dir(filepath.Dir(file))
		fresh, e := New(context.Background(), Config{SourceRoot: sourceRoot, StorageRoot: storeRoot, Keys: verifier.Config{HMAC: &scy.Resource{URL: filepath.Join(storeRoot, "fixture-hmac")}}, IdentityPolicy: auth.Policy{Issuer: "fixture", Audience: "mechanize", Algorithms: []string{"HS256"}, Clients: map[string]string{"fixture-agent": "Fixture"}}, Users: []User{{Subject: "actor", DesktopAccess: true}}})
		if e != nil {
			t.Fatal(e)
		}
		defer func() { fresh.chrome = nil; _ = fresh.Close(context.Background()) }()
		// Replace only the fixture transport callback; all schema, durable execution,
		// runtime admission and Host consent/protection code remains the real path.
		if e = fresh.Runtime.Shutdown(ctx); e != nil {
			t.Fatal(e)
		}
		if e = fresh.durable.Close(ctx); e != nil {
			t.Fatal(e)
		}
		publicReads := 0
		_, nativeFixture := launchOnlyFixture(t)
		nativeFixture.ready.AllApplicationsQualified = true
		nativeFixture.ready.QualifiedBundles = nil
		nativeFixture.manager.options.EnrolledScope = func(c context.Context, actor auth.Principal) (sessionpkg.Scope, error) {
			user, err := fresh.authorize(c, actor)
			return nativeUserScope(user), err
		}
		nativeHelper := &restartNativeLaunchHelper{hostDispatchHelper: &hostDispatchHelper{controlFixture: nativeFixture}, principal: p}
		nativeHelper.launch = func(c context.Context) (sessionpkg.ProcessIdentity, error) {
			var err error
			current, err = bridge.call(c, protectionWorkerRequest{Op: "launchChrome"})
			if err != nil {
				return sessionpkg.ProcessIdentity{}, err
			}
			identity, live, err := sessionpkg.InspectProcess(current.ProcessPID)
			if err != nil || !live || identity.StartToken == birth.StartToken || identity.UID != birth.UID || identity.Executable != birth.Executable {
				return sessionpkg.ProcessIdentity{}, errors.New("fresh Chrome kernel identity unavailable")
			}
			currentBirth = identity
			return identity, nil
		}
		nativeFixture.manager.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) { return nativeHelper, nil }
		fresh.nativeControl = nativeFixture.manager
		store, e := durable.New(durable.Options{SourceRoot: sourceRoot, StorageRoot: storeRoot, PrepareStepAuthority: func(c context.Context, actor auth.Principal, step model.Step) (context.Context, int, error) {
			if step.Target.Surface.Kind == "native" {
				return fresh.prepareStepExecutor(c, actor, step)
			}
			now, live, err := sessionpkg.InspectProcess(currentBirth.PID)
			if err != nil || !live || now != currentBirth {
				return nil, 0, auth.ErrUnauthorized
			}
			return c, 88, nil
		}, LeaseEpoch: func(c context.Context, _ auth.Principal) (int, error) {
			now, live, e := sessionpkg.InspectProcess(currentBirth.PID)
			if e != nil || !live || now != currentBirth {
				return 0, auth.ErrUnauthorized
			}
			return 88, nil
		}}, func(c context.Context, actor auth.Principal, step model.Step, values map[string]model.Value) (automation.StepResult, error) {
			if step.Target.Surface.Kind == "native" {
				return fresh.execute(c, actor, step, values)
			}
			if step.Action != "element.read" || step.Target.Surface.Origin != current.Origin || step.Target.Surface.TabID != (chrome.Document{Identity: current.PublicIdentity}).QualifiedTabID() {
				return automation.StepResult{}, auth.ErrUnauthorized
			}
			lease, e := fresh.AuthorizeOperation(c, actor, step.Target.Surface, false, consent.Observe)
			if e != nil {
				return automation.StepResult{}, e
			}
			defer lease.Release()
			actual, e := bridge.call(lease.Context, protectionWorkerRequest{Op: "publicRead"})
			if e != nil || !actual.Available || !actual.ContainsFixture || actual.ReadCalls != 1 || actual.PublicIdentity != current.PublicIdentity {
				return automation.StepResult{}, errors.New("fresh production worker public read unavailable")
			}
			publicReads++
			return automation.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
		})
		if e != nil {
			t.Fatal(e)
		}
		fresh.durable = store
		fresh.applicationAccess = &applicationAccessService{invoke: store.InvokePrivateComponent, enrolled: fresh.enrolled}
		rt, e := automation.NewWithOptions(store.Execute, automation.Options{PreparePlan: store.PreparePlan, LoadResume: store.LoadResume, AttachInitialOperation: func(c context.Context, actor auth.Principal, run string, rev int, session, operation string) error {
			_, e := store.AttachOperation(c, actor, run, rev, session, operation)
			return e
		}})
		if e != nil {
			t.Fatal(e)
		}
		fresh.Runtime = rt
		fresh.consent, e = NewConsentBroker(ConsentBrokerOptions{Invoke: store.InvokePrivateComponent, Enrolled: fresh.enrolled, SessionOwned: rt.CheckSession, Policy: fresh.ConsentPolicy})
		if e != nil {
			t.Fatal(e)
		}
		fresh.nativeVaultRecords, e = vault.NewRecordStore(filepath.Join(storeRoot, "records"), "fixture-v1", &vault.Cipher{Keys: credentialFixtureKey{calls: reads}})
		if e != nil {
			t.Fatal(e)
		}
		fresh.vaultExposure, e = vault.NewGuardedExposureGate(func(context.Context) error { return nil })
		if e != nil {
			t.Fatal(e)
		}
		fresh.chrome, e = chrome.NewGateway(&chrome.Broker{}, chrome.GatewayOptions{})
		if e != nil {
			t.Fatal(e)
		}
		newSession, e := rt.Open(ctx, "fresh independently qualified fixture")
		if e != nil {
			t.Fatal(e)
		}
		input.SessionID = newSession.SessionID
		openStep := model.Step{ID: "reopen-chrome", Action: "app.open", Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.google.Chrome"}, Cardinality: "one"}, TimeoutMs: 10000, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"bundleID": {Kind: model.StringValue, String: "com.google.Chrome"}}}}
		if e = openStep.Validate(); e != nil {
			t.Fatal(e)
		}
		openPurpose := "Open Chrome after the original source exits"
		appRequest, e := fresh.consent.Request(ctx, p, newSession.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "com.google.Chrome"}, Modes: []consent.Mode{consent.Control}, Purpose: openPurpose, DurationSeconds: 120})
		if e != nil {
			t.Fatal("ordinary application Control request", e)
		}
		human, e := auth.WithNativeHuman(ctx)
		if e != nil {
			t.Fatal(e)
		}
		decision, _ := json.Marshal(map[string]any{"requestID": appRequest.ID, "decision": consent.AllowSession})
		approved, e := fresh.consent.NativeRPC(human, "decide", decision)
		if e != nil {
			t.Fatal(e)
		}
		appGrant, ok := approved.(*consent.Grant)
		if !ok {
			t.Fatal("application grant shape")
		}
		openContext := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: newSession.SessionID, GrantID: appGrant.ID, Purpose: openPurpose})
		if lease, e := fresh.authorizeNativeControlStep(openContext, p, openStep); e == nil {
			lease.Release()
			t.Fatal("fresh Host allowed app.open while original protected Chrome birth remained live")
		}
		if _, e = bridge.call(ctx, protectionWorkerRequest{Op: "stopChrome"}); e != nil {
			t.Fatal("normal Chrome close", e)
		}
		check, cancel := context.WithTimeout(ctx, 3*time.Second)
		e = sessionpkg.VerifyProcessBirthAbsent(check, birth.UID, birth.StartToken)
		cancel()
		if e != nil {
			t.Fatal("original Chrome birth not independently absent", e)
		}
		launchOperation, e := rt.StartPlan(openContext, newSession.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{openStep}}, nil)
		if e != nil {
			t.Fatal("normal Chrome launch plan admission", e)
		}
		launchWait, stopLaunchWait := context.WithTimeout(ctx, 15*time.Second)
		launched, e := rt.Wait(launchWait, newSession.SessionID, launchOperation.ID)
		stopLaunchWait()
		if e != nil || launched.Status != manager.OperationSucceeded || nativeHelper.mutations != 1 || !nativeHelper.sawIntent || nativeFixture.alive {
			t.Fatalf("normal durable Chrome app.open failed: operation=%+v err=%v launches=%d committedIntent=%v helperAlive=%v", launched, e, nativeHelper.mutations, nativeHelper.sawIntent, nativeFixture.alive)
		}
		launchRun, e := rt.RunReference(ctx, newSession.SessionID, launchOperation.ID)
		if e != nil {
			t.Fatal(e)
		}
		launchState, e := store.StateGet(ctx, p, launchRun)
		if e != nil || len(launchState.UnresolvedEffects) != 0 || len(launchState.Progress) != 1 {
			t.Fatal("launch durable outcome not confirmed", launchState, e)
		}
		if blocked, e := store.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
			t.Fatal("Chrome app.open changed retained private protection", e)
		}
		retained, e := store.StateGet(ctx, p, oldState.RunID)
		retainedJSON, _ := json.Marshal(retained)
		if e != nil || string(retainedJSON) != string(before) {
			t.Fatal("Chrome app.open changed activation UNKNOWN", e)
		}
		t.Log("Runtime/Endly/durable app.open: committed intent, normal native admission/consent, exactly one launch, independent process readback, cleanup and durable result confirmed; old protection/UNKNOWN retained")
		retired = true
		input.Surface.TabID = (chrome.Document{Identity: current.TargetIdentity}).QualifiedTabID()
		nextFixture := &credentialBrowserFixture{host: fresh, t: t}
		configure(nextFixture)
		fresh.credentials.browserFixture = nextFixture
		next, e := fresh.CredentialPrepare(ctx, p, input)
		if e != nil || next.State != "awaitingPreflight" || next.PreparationID == "" || next.PreparationID == ref.PreparationID {
			t.Fatal("normal source retirement blocked fresh preparation", next, e)
		}
		nextFixture.session = fresh.credentials.pending[next.PreparationID]
		ready, e := fresh.CredentialStatus(ctx, p, gateway.CredentialRefInput{SessionID: newSession.SessionID, PreparationID: next.PreparationID})
		if e != nil || ready.State != "ready" {
			t.Fatal("fresh private requalification failed", ready, e)
		}
		held := auth.WithConsentBinding(ctx, nextFixture.session.consent)
		if e = store.WithCredentialDeliveryComponents(held, p, func(c context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
			prep, rows, e := store.LoadCredentialRecovery(c, p, ref.PreparationID)
			if e != nil {
				return e
			}
			if prep.ProtectionState != "closed" || len(rows) != len(oldPrivate) {
				return errors.New("private history was removed")
			}
			old := map[string]data.CredentialDeliveryRecord{}
			for _, r := range oldPrivate {
				old[r.AttemptID] = r
			}
			for _, r := range rows {
				prior, ok := old[r.AttemptID]
				want := "closed"
				if prior.DispatchState == "unknown" {
					want = "retired"
				}
				if !ok || r.DispatchState != prior.DispatchState || r.ProtectionState != want || r.ChromeStartToken != birth.StartToken {
					return errors.New("private source outcome changed")
				}
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		plan := model.Plan{SchemaVersion: 1, Steps: []model.Step{{ID: "fresh-public-read", Action: "element.read", Target: model.Selector{Surface: model.Surface{Kind: "web", Origin: current.Origin, TabID: (chrome.Document{Identity: current.PublicIdentity}).QualifiedTabID()}, Locator: &model.Locator{Strategy: "role", Value: model.Value{Kind: model.StringValue, String: "document"}, Exact: true}, Cardinality: "one"}, Arguments: map[string]model.Value{"attribute": {Kind: model.StringValue, String: "text"}}, TimeoutMs: 10000, Effect: model.Effect{Class: model.ReadOnly}}}}
		started, e := rt.StartPlanWithRequest(held, newSession.SessionID, "new-public-read", plan, nil)
		if e != nil {
			t.Fatal(e)
		}
		waited, cancel := context.WithTimeout(held, 5*time.Second)
		completed, e := rt.Wait(waited, newSession.SessionID, started.ID)
		cancel()
		if e != nil || completed == nil || completed.Status != manager.OperationSucceeded || publicReads != 1 {
			t.Fatal("fresh durable public workflow failed", e)
		}
		if _, e = store.LoadResume(held, p, oldState.RunID, oldState.Revision, oldState.PlanID, oldState.ObjectiveID); !errors.Is(e, durable.ErrNeedsReconciliation) {
			t.Fatal("old UNKNOWN became resumable", e)
		}
		afterState, e := store.StateGet(held, p, oldState.RunID)
		if e != nil {
			t.Fatal(e)
		}
		after, _ := json.Marshal(afterState)
		if string(before) != string(after) || len(afterState.UnresolvedEffects) != 1 || activation.calls != 1 || nextFixture.fills != 0 || nextFixture.submits != 0 {
			t.Fatal("fresh executor rewrote or replayed original history")
		}
		t.Log("same-store acceptance: original process birth absent; fresh Host preparation and public workflow passed; original activation UNKNOWN and private dispatch history retained")
	}
	credentialHostFixtureFlow(t, "freshExecutor", credentialHostFixtureHooks{origin: initial.Origin, storageRoot: func(root string) { storeRoot = root }, configure: configure, exercise: exercise})
}
