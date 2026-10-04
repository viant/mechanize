package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/artifact"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/scy"
)

type windowFrameHostHelper struct {
	*controlFixture
	captured        chan struct{}
	continueCapture chan struct{}
	beforeClick     func(context.Context) error
	clicks          int
	permit          native.WindowFramePermit
}

func (f *windowFrameHostHelper) Call(ctx context.Context, r native.Request) (native.Reply, error) {
	reply := native.Reply{HelperEpoch: "fixture", RequestID: r.RequestID}
	switch r.Method {
	case "doctor":
		reply.Result, _ = json.Marshal(map[string]any{"axTrusted": true, "semanticEnabled": true, "captureGranted": true, "windowFrameClickEnabled": true})
	case "lease.install":
	case "windows.captureFrame":
		var params struct {
			Owner  native.WindowFrameOwner `json:"owner"`
			Bundle string                  `json:"expectedApp"`
			PID    int                     `json:"pid"`
			Birth  string                  `json:"processStartToken"`
			Window uint32                  `json:"windowId"`
		}
		json.Unmarshal(r.Params, &params)
		if r.Lease == nil {
			panic("missing frame fence")
		}
		if f.captured != nil {
			close(f.captured)
			select {
			case <-f.continueCapture:
			case <-ctx.Done():
				return reply, ctx.Err()
			}
		}
		var buf bytes.Buffer
		png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 16, 12)))
		sum := sha256.Sum256(buf.Bytes())
		now := time.Now()
		f.permit = native.WindowFramePermit{ID: "host-frame-permit", Owner: params.Owner, HelperEpoch: "fixture", FenceGeneration: r.Lease.Generation, BundleID: params.Bundle, PID: params.PID, ProcessStartToken: params.Birth, WindowID: params.Window, DisplayID: 1, Width: 16, Height: 12, Bounds: native.CaptureBounds{X: 10, Y: 20, Width: 16, Height: 12}, Scale: 1, ContentHash: hex.EncodeToString(sum[:]), CapturedAt: now, ExpiresAt: now.Add(native.WindowFramePermitLifetime)}
		reply.Result, _ = json.Marshal(map[string]any{"permit": f.permit, "pngBase64": base64.StdEncoding.EncodeToString(buf.Bytes())})
	case "windows.clickFrame":
		if f.beforeClick != nil {
			if err := f.beforeClick(ctx); err != nil {
				return reply, err
			}
		}
		f.clicks++
		var params struct {
			Owner native.WindowFrameOwner `json:"owner"`
			ID    string                  `json:"permitId"`
			X     int64                   `json:"x"`
			Y     int64                   `json:"y"`
		}
		json.Unmarshal(r.Params, &params)
		reply.Receipt = &native.Receipt{DispatchState: "dispatched", TargetRef: "window:17"}
		reply.Result, _ = json.Marshal(map[string]any{"permitId": params.ID, "owner": params.Owner, "pid": 42, "startToken": "100:1", "bundleID": "fixture.app", "windowId": 17, "identity": "window:17", "point": map[string]any{"x": params.X, "y": params.Y}, "requestId": r.RequestID, "observedAt": time.Now(), "businessSuccess": false})
	default:
		panic("frame route fallback: " + r.Method)
	}
	return reply, nil
}

func newWindowFrameHostFixture(t *testing.T) (*Host, *controlFixture, *windowFrameHostHelper, context.Context, model.Surface) {
	t.Helper()
	service, _, p, artifactRoot, options := artifactFixture(t)
	resolver, err := artifact.NewScyResolver(map[string]scy.Resource{"fixture-v1": {URL: filepath.Join(filepath.Dir(artifactRoot), "key.json")}})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.New(artifact.Config{Root: filepath.Join(filepath.Dir(artifactRoot), "frame-artifacts"), SourceKeyReference: "fixture-v1", Keys: resolver, MaxBytes: 1 << 20, NamespaceQuotaBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	options.Store = store
	p.ClientID = "frame-client"
	p.ClientName = "Frame Client"
	p.Scopes = append(p.Scopes, "desktop:control", "consent:admin")
	h, f := semanticFixture(t)
	f.principal = p
	f.ctx = auth.WithPrincipal(context.Background(), p)
	f.enrolled = []string{"fixture.app"}
	f.ready.QualifiedBundles = f.enrolled
	f.ready.EventPost = true
	f.ready.WindowFrameClickQualified = true
	f.manager.options.WindowFrameClick = true
	h.owner = f.owner
	h.artifacts = service
	h.users = map[string]User{p.Namespace: {NativeBundles: f.enrolled}}
	helper := &windowFrameHostHelper{controlFixture: f}
	f.manager.options.HelperFactory = func(_ context.Context, opts native.Options) (NativeControlHelper, error) {
		f.starts++
		f.mu.Lock()
		f.alive = true
		f.mu.Unlock()
		if !opts.AllowWindowFrameClick || opts.AllowMutations {
			t.Fatal("window frame enrollment widened authority")
		}
		return helper, nil
	}
	_, file, _, _ := runtime.Caller(0)
	h.durable, err = durable.New(durable.Options{SourceRoot: filepath.Dir(filepath.Dir(file)), StorageRoot: t.TempDir(), VerifyArtifact: service.VerifyArtifact, PrepareStepAuthority: h.prepareStepExecutor, LeaseEpoch: h.controlLeaseEpoch}, h.execute)
	if err != nil {
		t.Fatal(err)
	}
	options.Publish = h.durable.PublishArtifact
	h.Runtime, err = automation.NewWithOptions(h.durable.Execute, automation.Options{OnSessionClose: h.cancelWindowFrameSession, PreparePlan: h.durable.PreparePlan, CompleteObjective: h.durable.CompleteObjective, EvaluatePostcondition: h.durable.EvaluatePostcondition, AttachInitialOperation: func(ctx context.Context, p auth.Principal, run string, rev int, session, operation string) error {
		_, err := h.durable.AttachOperation(ctx, p, run, rev, session, operation)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := h.Runtime.Open(f.ctx, "frame fixture")
	if err != nil {
		t.Fatal(err)
	}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: h.durable.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: h.Runtime.CheckSession, Policy: h.ConsentPolicy})
	if err != nil {
		t.Fatal(err)
	}
	purpose := "Click captured fixture"
	request, err := h.consent.Request(f.ctx, p, opened.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "fixture.app"}, Modes: []consent.Mode{consent.Observe, consent.Control}, Purpose: purpose, DurationSeconds: 120})
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
	approved, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	ctx := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{GrantID: approved.(*consent.Grant).ID, SessionID: opened.SessionID, Purpose: purpose})
	t.Cleanup(func() { _ = h.Close(context.Background()) })
	return h, f, helper, ctx, model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "100:1"}
}
func capturedFrameHostStep(t *testing.T, ref string) model.Step {
	t.Helper()
	plan, err := script.Compile(`app("fixture.app",processId:42,processStartToken:"100:1").clickWindowFrame(captureRef:"` + ref + `",x:3,y:4)`)
	if err != nil {
		t.Fatal(err)
	}
	return plan.Steps[0]
}

func TestWindowFrameHostRetainedCapturePublishesAndDispatchesAfterRealCommittedIntent(t *testing.T) {
	h, f, helper, ctx, surface := newWindowFrameHostFixture(t)
	imageRef, provenanceRef, frame, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17)
	if err != nil {
		t.Fatal(err)
	}
	if imageRef.ID == "" || provenanceRef.ID == "" || f.starts != 1 {
		t.Fatal("capture did not retain qualified helper and publish evidence")
	}
	raw, err := h.artifacts.Read(ctx, f.principal, provenanceRef)
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		Artifact data.ArtifactReference   `json:"artifact"`
		Permit   native.WindowFramePermit `json:"permit"`
		Binding  auth.ConsentBinding      `json:"consentBinding"`
	}
	if json.Unmarshal(raw, &provenance) != nil || provenance.Artifact != imageRef || provenance.Permit.ID != frame.Permit.ID || provenance.Binding.Purpose != "Click captured fixture" {
		t.Fatal("durable provenance changed")
	}
	var captured context.Context
	helper.beforeClick = func(call context.Context) error {
		captured = call
		intent, err := data.RequireCommittedStepIntent(call, f.principal)
		if err != nil {
			return err
		}
		metadata, ok := automation.ExecutionFromContext(call)
		if !ok || intent.OperationID != metadata.OperationID || intent.SessionID != frame.Permit.Owner.SessionID || uint64(intent.LeaseEpoch) != frame.Permit.FenceGeneration {
			return errors.New("click lost committed current intent")
		}
		return nil
	}
	binding, _ := auth.ConsentBindingFromContext(ctx)
	step := capturedFrameHostStep(t, frame.Permit.ID)
	step.Effect.BusinessKey = map[string]model.Value{"operation": {Kind: model.StringValue, String: "fixture-window-click"}}
	operation, err := h.Runtime.StartPlan(ctx, binding.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{step}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	finished, err := h.Runtime.Wait(wait, binding.SessionID, operation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if helper.clicks != 1 || finished.Status != "failed" || captured == nil {
		t.Fatalf("expected one unverified click: status=%s clicks=%d error=%s", finished.Status, helper.clicks, finished.Error)
	}
	if _, err := data.RequireCommittedStepIntent(context.WithoutCancel(captured), f.principal); err == nil {
		t.Fatal("intent survived dispatch")
	}
	_, err = h.durable.Execute(context.WithoutCancel(captured), f.principal, step, nil)
	if !errors.Is(err, durable.ErrNeedsReconciliation) || helper.clicks != 1 {
		t.Fatalf("unverified click replay barrier lost: %v", err)
	}
}

func TestWindowFrameHostCreationConcurrentCallsCancellationAndExpiryFailClosed(t *testing.T) {
	h, f, helper, ctx, surface := newWindowFrameHostFixture(t)
	helper.captured = make(chan struct{})
	helper.continueCapture = make(chan struct{})
	captureCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, _, _, err := h.CaptureWindowFrame(captureCtx, f.principal, surface, 42, 17); done <- err }()
	select {
	case <-helper.captured:
	case <-time.After(30 * time.Second):
		t.Fatal("fixture capture not reached")
	}
	h.frameMu.Lock()
	record := h.framePermits[f.principal.Namespace]
	h.frameMu.Unlock()
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: f.principal.Namespace, LeaseEpoch: record.admission.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	intent := data.CommittedStepIntent{Namespace: f.principal.Namespace, ClientID: f.principal.ClientID, RunID: "run", PlanID: "plan", StepID: "step", AttemptID: "attempt", EffectID: "effect", LeaseEpoch: record.admission.Epoch, RunRevision: 1, SessionID: record.binding.SessionID, OperationID: "operation"}
	committed, revoke, err := data.WithCommittedStepIntent(scoped, f.principal, intent)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := h.consumeWindowFrame(committed, f.principal, capturedFrameHostStep(t, "guessed"), nil, NativeControlAdmission{}); err == nil {
				t.Error("creating permit admitted early click")
			}
			h.expireWindowFrame(record)
		}()
	}
	if _, _, _, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17); err == nil {
		t.Fatal("concurrent capture admitted")
	}
	cancel()
	wg.Wait()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled capture issued permit")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("canceled creation failed to settle")
	}
	h.frameMu.Lock()
	remaining := h.framePermits[f.principal.Namespace]
	h.frameMu.Unlock()
	if remaining != nil || helper.clicks != 0 {
		t.Fatal("canceled creation leaked permit/input")
	}
}

func TestWindowFrameHostPermitOwnershipIntentReuseAndEpochGuards(t *testing.T) {
	for _, mode := range []string{"valid", "artifact", "client", "user", "session", "grant", "purpose", "expired", "revoked", "epoch", "restart", "noIntent"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "permit-owner", []string{"desktop:control", "desktop:observe"})
			p.ClientID = "client"
			binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "Click fixture"}
			ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), binding)
			admitted := NativeControlAdmission{Gateway: &native.Gateway{}, Epoch: 1}
			retained, cancel := context.WithCancel(ctx)
			defer cancel()
			record := &windowFramePermit{principal: p, binding: binding, surface: model.Surface{Kind: "native", BundleID: "fixture.app", ProcessID: 42, ProcessStartToken: "100:1"}, frame: native.WindowFrameCapture{Permit: native.WindowFramePermit{ID: "issued-permit", Width: 16, Height: 12, ExpiresAt: time.Now().Add(time.Minute)}}, admission: admitted, lease: &consent.Lease{Context: retained, Release: func() {}}, cancel: cancel, ready: true}
			h := &Host{framePermits: map[string]*windowFramePermit{p.Namespace: record}}
			step := capturedFrameHostStep(t, "issued-permit")
			switch mode {
			case "artifact":
				step.Arguments["frameClick"].Object["captureRef"] = model.Value{Kind: model.StringValue, String: "image-artifact-id"}
			case "client":
				p.ClientID = "foreign"
			case "user":
				other, _ := auth.NewPrincipal("fixture", "", "foreign", p.Scopes)
				other.ClientID = p.ClientID
				p = other
			case "session":
				binding.SessionID = "foreign"
			case "grant":
				binding.GrantID = "foreign"
			case "purpose":
				binding.Purpose = "Changed purpose"
			case "expired":
				record.frame.Permit.ExpiresAt = time.Now().Add(-time.Second)
			case "revoked":
				cancel()
			case "epoch":
				admitted.Epoch = 2
			case "restart":
				admitted.Gateway = &native.Gateway{}
			}
			ctx = auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), binding)
			scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: admitted.Epoch})
			if err != nil {
				t.Fatal(err)
			}
			committed := scoped
			revoke := func() {}
			if mode != "noIntent" {
				committed, revoke, err = data.WithCommittedStepIntent(scoped, p, data.CommittedStepIntent{Namespace: p.Namespace, ClientID: p.ClientID, RunID: "run", PlanID: "plan", StepID: "step", AttemptID: "attempt", EffectID: "effect", LeaseEpoch: admitted.Epoch, RunRevision: 1, SessionID: binding.SessionID, OperationID: "operation"})
				if err != nil {
					t.Fatal(err)
				}
			}
			defer revoke()
			lease, finish, err := h.consumeWindowFrame(committed, p, step, nil, admitted)
			if mode != "valid" {
				if err == nil || lease != nil || record.used {
					t.Fatal("invalid capture permit admitted")
				}
				return
			}
			if err != nil || lease == nil || finish == nil {
				t.Fatal(err)
			}
			if _, err = data.RequireCommittedStepIntent(lease.Context, p); err != nil {
				t.Fatal("retained cancellation replaced committed context")
			}
			if _, _, err = h.consumeWindowFrame(committed, p, step, nil, admitted); err == nil {
				t.Fatal("permit consumed twice")
			}
			cancel()
			select {
			case <-lease.Context.Done():
			case <-time.After(time.Second):
				t.Fatal("retained consent revoke did not cancel dispatch")
			}
			finish()
		})
	}
}

func TestWindowFrameControlUnknownReceiptRetainsPhysicalBarrierAndRejectsRawPointer(t *testing.T) {
	_, f := semanticFixture(t)
	f.manager.options.WindowFrameClick = true
	f.ready.WindowFrameClickQualified = true
	f.ready.EventPost = true
	f.principal.ClientID = "client"
	f.ctx = auth.WithConsentBinding(auth.WithPrincipal(context.Background(), f.principal), auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "Click fixture"})
	f.callErr = &native.NativeError{Code: "clickUnknown", Stage: "native", DispatchState: "unknown"}
	f.unknown = true
	f.admit(t)
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	caller := f.caller()
	if _, err := caller.Call(f.ctx, native.Request{Method: "input.pointer", Lease: &lease}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("global pointer route admitted")
	}
	params, _ := json.Marshal(map[string]any{"expectedApp": "com.fixture.app", "owner": native.WindowFrameOwner{Namespace: f.principal.Namespace, ClientID: f.principal.ClientID, SessionID: "session"}, "permitId": "permit", "x": 1, "y": 2})
	if _, err := caller.Call(f.ctx, native.Request{Method: "windows.clickFrame", Lease: &lease, Params: params}); err == nil || !f.manager.held.inhibited {
		t.Fatal("unknown frame input retained authority")
	}
	if _, err := f.manager.Revoke(f.ctx, f.principal); !errors.Is(err, ErrNativeControlCleanupUnknown) {
		t.Fatal("unknown click released physical barrier")
	}
}

func TestWindowFrameOwnedMCPSessionCloseCancelsReadyAndCreatingIntervals(t *testing.T) {
	for _, mode := range []string{"ready", "creating"} {
		t.Run(mode, func(t *testing.T) {
			h, f, helper, ctx, surface := newWindowFrameHostFixture(t)
			var old *windowFramePermit
			done := make(chan error, 1)
			if mode == "creating" {
				helper.captured = make(chan struct{})
				helper.continueCapture = make(chan struct{})
				go func() { _, _, _, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17); done <- err }()
				select {
				case <-helper.captured:
				case <-time.After(30 * time.Second):
					t.Fatal("creating capture not reached")
				}
			} else {
				if _, _, _, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17); err != nil {
					t.Fatal(err)
				}
			}
			h.frameMu.Lock()
			old = h.framePermits[f.principal.Namespace]
			h.frameMu.Unlock()
			server, err := gateway.New(gateway.Dependencies{Runtime: h.Runtime, Policy: h.Policy})
			if err != nil {
				t.Fatal(err)
			}
			client := server.AsClient(ctx)
			if _, err = client.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			binding, _ := auth.ConsentBindingFromContext(ctx)
			result, err := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_session_close", Arguments: map[string]any{"sessionId": binding.SessionID}})
			if err != nil || result.IsError != nil && *result.IsError {
				t.Fatalf("session close failed: %v %+v", err, result)
			}
			if mode == "creating" {
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("closed creating session issued a permit")
					}
				case <-time.After(15 * time.Second):
					t.Fatal("closed creation cleanup not joined")
				}
			}
			h.frameMu.Lock()
			remaining := h.framePermits[f.principal.Namespace]
			h.frameMu.Unlock()
			if remaining != nil || helper.clicks != 0 || h.Runtime.CheckSession(ctx, f.principal, binding.SessionID) == nil {
				t.Fatal("closed session retained input interval")
			}
			// Recreate a separately approved owned session, then fire the old expiration.
			helper.captured = nil
			helper.continueCapture = nil
			opened, err := h.Runtime.Open(f.ctx, "new frame session")
			if err != nil {
				t.Fatal(err)
			}
			request, err := h.consent.Request(f.ctx, f.principal, opened.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "fixture.app"}, Modes: []consent.Mode{consent.Observe, consent.Control}, Purpose: binding.Purpose, DurationSeconds: 120})
			if err != nil {
				t.Fatal(err)
			}
			human, _ := auth.WithNativeHuman(f.ctx)
			decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
			approved, err := h.consent.NativeRPC(human, "decide", decision)
			if err != nil {
				t.Fatal(err)
			}
			next := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: opened.SessionID, GrantID: approved.(*consent.Grant).ID, Purpose: binding.Purpose})
			if _, _, _, err = h.CaptureWindowFrame(next, f.principal, surface, 42, 17); err != nil {
				t.Fatal(err)
			}
			h.expireWindowFrame(old)
			h.frameMu.Lock()
			current := h.framePermits[f.principal.Namespace]
			h.frameMu.Unlock()
			if current == nil || current == old || current.lease.Context.Err() != nil || current.admission.Epoch <= old.admission.Epoch {
				t.Fatal("old expiration reaped new qualified interval")
			}
			if err = h.Runtime.Close(next, opened.SessionID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWindowFrameReservationRechecksSessionAfterPrewarmBoundary(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "close-reservation", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	h := &Host{}
	rt, err := automation.NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
		return automation.StepResult{}, nil
	}, automation.Options{OnSessionClose: h.cancelWindowFrameSession})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = rt
	opened, err := rt.Open(ctx, "reservation boundary")
	if err != nil {
		t.Fatal(err)
	}
	if err = rt.CheckSession(ctx, p, opened.SessionID); err != nil {
		t.Fatal(err)
	} // completed prewarm-side check
	if err = rt.Close(ctx, opened.SessionID); err != nil {
		t.Fatal(err)
	} // hook finds no record
	record := &windowFramePermit{principal: p, binding: auth.ConsentBinding{SessionID: opened.SessionID}, cancel: func() {}, done: make(chan struct{})}
	if err = h.reserveWindowFrame(ctx, p, record); err == nil {
		t.Fatal("closed session passed stale prewarm check")
	}
	if h.framePermits[p.Namespace] != nil {
		t.Fatal("late capture reservation survived owned close")
	}
}

func TestWindowFrameHostShutdownDuringCreatingCaptureJoinsAndClosesAdmission(t *testing.T) {
	h, f, helper, ctx, surface := newWindowFrameHostFixture(t)
	helper.captured = make(chan struct{})
	helper.continueCapture = make(chan struct{})
	captureDone := make(chan error, 1)
	go func() { _, _, _, err := h.CaptureWindowFrame(ctx, f.principal, surface, 42, 17); captureDone <- err }()
	select {
	case <-helper.captured:
	case <-time.After(30 * time.Second):
		t.Fatal("blocked capture not reached")
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := h.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-captureDone:
		if err == nil {
			t.Fatal("shutdown issued permit")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown returned before producer cleanup")
	}
	h.frameMu.Lock()
	remaining := len(h.framePermits)
	closed := h.framesClosed
	h.frameMu.Unlock()
	if remaining != 0 || !closed || helper.clicks != 0 {
		t.Fatal("shutdown retained capture/input interval")
	}
}
