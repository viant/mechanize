package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/vault"
)

// Real canonical controller MCP, Host admission and generated Datly writers.
// Only the OS capture/input and signed Chrome lifetime proofs are fixture seams;
// their production exact-process/origin checks are tested in backend/chrome.
func TestControllerSavedPolicyCanonicalMCPWithoutApprovalLoop(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "controller-owner", []string{"desktop:observe", "desktop:control"})
	p.ClientID = "controller:verified"
	p.ClientName = "Verified web fixture"
	ctx := auth.WithPrincipal(context.Background(), p)
	_, file, _, _ := runtime.Caller(0)
	scope := data.Scope{Namespace: p.Namespace}
	scoped, _ := data.WithScope(ctx, scope)
	store, err := datahost.Open(scoped, filepath.Dir(filepath.Dir(file)), t.TempDir(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Shutdown(context.Background())
	lifetime, stop := context.WithCancel(context.Background())
	defer stop()
	expires := time.Now().Add(2 * time.Minute)
	var secure atomic.Bool
	var inputs atomic.Int32
	gate, _ := vault.NewGuardedExposureGate(func(context.Context) error {
		if secure.Load() {
			return vault.ErrEntryProtected
		}
		return nil
	})
	h := &Host{users: map[string]User{p.Namespace: {DesktopAccess: true}}, vaultExposure: gate}
	rt, err := automation.New(func(c context.Context, actor auth.Principal, step model.Step, _ map[string]model.Value) (automation.StepResult, error) {
		lease, e := h.AuthorizeOperation(c, actor, step.Target.Surface, true, consent.Control)
		if e != nil {
			return automation.StepResult{DispatchState: "notDispatched"}, e
		}
		defer lease.Release()
		if auth.NativeHuman(lease.Context) {
			t.Error("input got human authority")
		}
		inputs.Add(1)
		return automation.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = rt
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
		return store.InvokeComponent(c, r)
	}, Enrolled: h.enrolled, SessionOwned: rt.CheckSession, Policy: h.ConsentPolicy, ControllerPolicy: func(c context.Context, actor auth.Principal) (context.Context, time.Time, func(), error) {
		if actor.ClientID != p.ClientID || lifetime.Err() != nil || auth.NativeHuman(c) {
			return nil, time.Time{}, nil, auth.ErrUnauthorized
		}
		bound, cancel := context.WithDeadline(c, expires)
		detach := context.AfterFunc(lifetime, cancel)
		return bound, expires, func() { detach(); cancel() }, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	caller := &observeRootCaller{}
	ng, _ := native.NewGateway(caller, native.GatewayOptions{AllowedBundles: []string{"fixture.app"}})
	h.nativeByUser = map[string]*native.Gateway{p.Namespace: ng}
	var pixels bytes.Buffer
	_ = png.Encode(&pixels, image.NewRGBA(image.Rect(0, 0, 2, 2)))
	digest := sha256.Sum256(pixels.Bytes())
	server, err := gateway.New(gateway.Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) {
		return script.Policy{AllowAllNative: true, AllowAllWeb: true, AllowMutation: true, Capabilities: map[string]bool{"native:semanticPress": true, "native:idLocator": true}}, nil
	}, ObserveNativeRoot: h.ObserveNativeRoot, CaptureWindow: func(c context.Context, actor auth.Principal, s model.Surface, pid int32, window uint32) (data.ArtifactReference, native.CapturedImage, error) {
		lease, e := h.AuthorizeOperation(c, actor, s, false, consent.Observe)
		if e != nil {
			return data.ArtifactReference{}, native.CapturedImage{}, e
		}
		defer lease.Release()
		return data.ArtifactReference{ID: "fixture-image", ContentHash: hex.EncodeToString(digest[:]), SizeBytes: pixels.Len(), MediaType: "image/png", KeyReference: "fixture-key"}, native.CapturedImage{PNG: pixels.Bytes(), Metadata: native.CaptureMetadata{BundleID: s.BundleID, PID: pid, WindowID: window, Identity: "window:42", Bytes: pixels.Len(), Width: 2, Height: 2, Scale: 1, CoordinateSpace: "globalLogicalPoints", Bounds: native.CaptureBounds{Width: 2, Height: 2}}}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := gateway.NewControllerDispatcher(server, rt)
	if err != nil {
		t.Fatal(err)
	}
	id := chrome.ControllerIdentity{Principal: p, ConversationID: "connection", Origin: "https://fixture.test", DocumentID: "controller-doc"}
	call := func(name string, args any, success bool) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(args)
		out, e := dispatcher.CallTool(ctx, id, chrome.ControllerToolCall{Name: name, Arguments: raw})
		if e != nil {
			t.Fatal(e)
		}
		failed := out.IsError != nil && *out.IsError
		if failed == success {
			t.Fatalf("%s unexpected error=%v: %+v", name, failed, out.StructuredContent)
		}
		encoded, _ := json.Marshal(out)
		if strings.Contains(string(encoded), "PRIVATE_VALUE") {
			t.Fatal("native value escaped")
		}
		var body map[string]any
		raw, _ = json.Marshal(out.StructuredContent)
		_ = json.Unmarshal(raw, &body)
		return body
	}
	session := call("mechanize_session_open", map[string]any{"name": "policy fixture"}, true)["sessionId"].(string)
	surface := model.Surface{Kind: "native", BundleID: "fixture.app"}
	observe := map[string]any{"sessionId": session, "purpose": "Public automation", "surface": surface, "nativeRoot": "menuBar"}
	call("mechanize_observe", observe, true)
	capture := map[string]any{"sessionId": session, "purpose": "Public automation", "surface": surface, "pid": 123, "windowId": 42}
	call("mechanize_capture", capture, true)
	run := map[string]any{"sessionId": session, "purpose": "Public automation", "clientRequestId": "once", "source": `app("fixture.app").getById("save").click()`}
	operation := call("mechanize_step_run", run, true)["operationId"].(string)
	until := time.Now().Add(5 * time.Second)
	var status map[string]any
	for time.Now().Before(until) {
		status = call("mechanize_operation_status", map[string]any{"sessionId": session, "operationId": operation}, true)
		if status["executionStatus"] != "running" && status["executionStatus"] != "queued" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if inputs.Load() != 1 {
		t.Fatalf("authorized input count=%d status=%v", inputs.Load(), status)
	}
	call("mechanize_step_run", run, true)
	if inputs.Load() != 1 {
		t.Fatal("replayed effect")
	}
	if len(h.consent.policyGrants) != 1 {
		t.Fatal("observe/capture/control did not reuse exact real binding", len(h.consent.policyGrants))
	}
	// Source protection is not cleared by policy authorization; active secure
	// Vault UI remains excluded, even though normal native capture is allowed.
	privateSurface := model.Surface{Kind: "web", Origin: "https://private.fixture.test"}
	privateLease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session, Purpose: "Public automation"})), p, privateSurface, true, consent.Control)
	if e != nil {
		t.Fatal(e)
	}
	privateContext := context.WithoutCancel(privateLease.Context)
	privateLease.Release()
	retained, e := gate.BeginDelivery(privateContext, vault.Binding{SessionID: session, DocumentID: "private-original", NavigationID: "private-navigation", Target: vault.Target{Origin: "https://private.fixture.test", Account: "opaque"}}, func(c context.Context) error {
		lease, e := h.authorizeConsentOperation(consent.RequireReusableGrant(c), p, privateSurface, true, consent.Control)
		if lease != nil {
			lease.Release()
		}
		return e
	}, func(context.Context) error { return vault.ErrEntryCleanup })
	if e != nil {
		t.Fatal(e)
	}
	defer retained.Retire()
	call("mechanize_capture", capture, true)
	blockedContext := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session, Purpose: "Public automation"})
	if lease, e := h.AuthorizeOperation(blockedContext, p, model.Surface{Kind: "web", Origin: "https://private.fixture.test"}, false, consent.Observe); lease != nil || e != vault.ErrDeliveryProtected {
		t.Fatal("policy bypassed browser credential protection", e)
	}
	if release, e := gate.AcquireExposureContext(ctx); release != nil || e != vault.ErrDeliveryProtected {
		t.Fatal("native capture erased retained private protection", e)
	}
	secure.Store(true)
	call("mechanize_capture", capture, false)
	secure.Store(false)
	observe["sessionId"] = "foreign"
	call("mechanize_observe", observe, false)
	observe["sessionId"] = session
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session, Purpose: "Public automation"})
	held, e := h.AuthorizeOperation(bound, p, surface, false, consent.Observe)
	if e != nil {
		t.Fatal(e)
	}
	defer held.Release()
	stop()
	select {
	case <-held.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel retained lease")
	}
	call("mechanize_observe", observe, false)
	call("mechanize_capture", capture, false)
	if inputs.Load() != 1 {
		t.Fatal("denial changed prior input count")
	}
}
