package host

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/vault"
)

type activateTabFixture struct {
	pending               chan struct{}
	pendingReady          chan struct{}
	t                     *testing.T
	observer              *durable.Builder
	prepares, activations int
	unknown               bool
	unsupported           bool
}
type activateTabFixtureKey struct{}

func (f *activateTabFixture) PrepareActivateTab(ctx context.Context, p auth.Principal, origin, tabHandle string) (context.Context, int, error) {
	f.prepares++
	if f.unsupported {
		return nil, 0, &model.MechanizeError{Code: "unsupportedWorker", Message: "PRIVATE_CANARY", DispatchState: "notDispatched"}
	}
	if origin != "https://fixture.test" || tabHandle != "profile/browser/42" {
		return nil, 0, auth.ErrUnauthorized
	}
	return context.WithValue(ctx, activateTabFixtureKey{}, origin), 77, nil
}
func (f *activateTabFixture) ExecuteActivateTab(ctx context.Context, p auth.Principal, origin, tabHandle, attempt string, admit func(context.Context) error) (automation.StepResult, error) {
	return f.executeActivateTab(ctx, p, origin, tabHandle, attempt, admit, nil)
}

// ExecuteActivateTabBound preserves the dormant binding fixture separately from
// the normal activation path; it is not used by the deployed Host interface.
func (f *activateTabFixture) ExecuteActivateTabBound(ctx context.Context, p auth.Principal, origin, tabHandle, attempt string, admit func(context.Context) error, commit func(context.Context, chrome.ActivationBinding) error) (automation.StepResult, error) {
	if commit == nil {
		return automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, errors.New("binding callback required")
	}
	return f.executeActivateTab(ctx, p, origin, tabHandle, attempt, admit, commit)
}
func (f *activateTabFixture) executeActivateTab(ctx context.Context, p auth.Principal, origin, tabHandle, attempt string, admit func(context.Context) error, commit func(context.Context, chrome.ActivationBinding) error) (automation.StepResult, error) {
	fail := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if ctx.Value(activateTabFixtureKey{}) != origin || tabHandle != "profile/browser/42" || admit == nil || admit(ctx) != nil {
		return fail, auth.ErrUnauthorized
	}
	intent, e := data.RequireCommittedStepIntent(ctx, p)
	if e != nil || intent.LeaseEpoch != 77 || attempt != data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID) {
		f.t.Fatal("tab activation preceded committed bound intent", e)
	}
	// A separately authorized Datly host must read the committed intent through
	// its generated StateGet component before activation.
	state, e := f.observer.StateGet(auth.WithPrincipal(context.Background(), p), p, intent.RunID)
	if e != nil || len(state.UnresolvedEffects) != 1 {
		f.t.Fatal("tab activation ran before actual commit/readback", e)
	}
	if commit != nil {
		binding := chrome.ActivationBinding{Namespace: p.Namespace, ClientID: p.ClientID, ProfileChannel: "profile", BrowserInstance: "browser", Origin: origin, BrowserAttemptID: attempt, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("a", 64), TabID: 42, ChromePID: 101, ChromeStartToken: "100:1", NativeHostPID: 102, NativeHostStartToken: "100:2", FingerprintVersion: 1}
		binding.FingerprintSHA256 = data.BrowserActivationFingerprint(data.BrowserActivationBindingAuthority{ProfileChannel: binding.ProfileChannel, BrowserInstance: binding.BrowserInstance, BrowserAttemptID: binding.BrowserAttemptID, Origin: binding.Origin, TabID: binding.TabID, BrokerEpoch: binding.BrokerEpoch, ChannelEpoch: binding.ChannelEpoch, ScopeHash: binding.ScopeHash})
		if e := commit(ctx, binding); e != nil {
			return fail, e
		}
		retained, e := f.observer.BrowserActivationBinding(auth.WithPrincipal(context.Background(), p), p, attempt)
		if e != nil || retained.DurableAttemptID != intent.AttemptID || retained.EndlySessionID != intent.SessionID || retained.ChromePID != 101 || retained.FingerprintDigest != binding.FingerprintSHA256 {
			f.t.Fatal("activation input preceded actual binding commit/readback", e)
		}
	}
	if f.pending != nil {
		close(f.pendingReady)
		select {
		case <-f.pending:
		case <-ctx.Done():
			return automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}, ctx.Err()
		}
	}
	f.activations++
	if f.unknown {
		return automation.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("PRIVATE_CANARY lost response")
	}
	return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
}
func TestActivateTabHostMCPDurableActivationAndUnknownNeverReplay(t *testing.T) {
	for _, mode := range []string{"activated", "unknown", "unsupported", "pending"} {
		t.Run(mode, func(t *testing.T) {
			unknown := mode == "unknown"
			p, _ := auth.NewPrincipal("fixture", "", "tab-owner", []string{"desktop:control", "desktop:observe", "consent:admin"})
			p.ClientID = "tab-client"
			p.ClientName = "Tab client"
			ctx := auth.WithPrincipal(context.Background(), p)
			_, file, _, _ := runtime.Caller(0)
			source := filepath.Dir(filepath.Dir(file))
			storage := t.TempDir()
			gate, _ := vault.NewGuardedExposureGate(func(context.Context) error { return vault.ErrEntryProtected })
			fixture := &activateTabFixture{t: t, unknown: unknown, unsupported: mode == "unsupported"}
			if mode == "pending" {
				fixture.pending = make(chan struct{})
				fixture.pendingReady = make(chan struct{})
			}
			h := &Host{users: map[string]User{p.Namespace: {Subject: p.Subject, WebOrigins: []string{"https://fixture.test"}}}, vaultExposure: gate, activateTabFixture: fixture}
			noNative := func(context.Context, auth.Principal) (int, error) {
				t.Fatal("origin activation borrowed native/renderer lease")
				return 0, nil
			}
			store, e := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: noNative, PrepareStepAuthority: h.prepareStepExecutor}, h.execute)
			if e != nil {
				t.Fatal(e)
			}
			h.durable = store
			defer store.Close(context.Background())
			observer, e := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: noNative}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				t.Fatal("generated Datly observer dispatched")
				return automation.StepResult{}, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			defer observer.Close(context.Background())
			fixture.observer = observer
			rt, e := automation.NewWithOptions(store.Execute, automation.Options{PreparePlan: store.PreparePlan, AttachInitialOperation: func(c context.Context, p auth.Principal, run string, rev int, session, operation string) error {
				_, e := store.AttachOperation(c, p, run, rev, session, operation)
				return e
			}})
			if e != nil {
				t.Fatal(e)
			}
			h.Runtime = rt
			session, e := rt.Open(ctx, "Activate tab fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer rt.Close(ctx, session.SessionID)
			h.consent, e = NewConsentBroker(ConsentBrokerOptions{Invoke: store.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: rt.CheckSession, Policy: h.ConsentPolicy})
			if e != nil {
				t.Fatal(e)
			}
			server, e := gateway.New(gateway.Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserActivateTab: h.BrowserActivateTab})
			if e != nil {
				t.Fatal(e)
			}
			client := server.AsClient(ctx)
			if _, e = client.Initialize(ctx); e != nil {
				t.Fatal(e)
			}
			args := map[string]any{"sessionId": session.SessionID, "clientRequestId": "one-explicit-activation", "origin": "https://fixture.test", "tabHandle": "profile/browser/42"}
			call := func(a map[string]any) *schema.CallToolResult {
				out, e := client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_activate_tab", Arguments: a})
				if e != nil {
					t.Fatal(e)
				}
				return out
			}
			denied := call(args)
			if denied.IsError == nil || !*denied.IsError || fixture.prepares != 0 || fixture.activations != 0 {
				t.Fatal("activation bypassed current Control consent")
			}
			bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Activate approved existing browser tab"})
			request, e := h.consent.Request(bound, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "origin", Origin: "https://fixture.test"}, Modes: []consent.Mode{consent.Control}, Purpose: "Activate approved existing browser tab", DurationSeconds: 120})
			if e != nil {
				t.Fatal(e)
			}
			human, _ := auth.WithNativeHuman(bound)
			decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
			if _, e = h.consent.NativeRPC(human, "decide", decision); e != nil {
				t.Fatal(e)
			}
			if _, e = observer.CredentialDeliveryBlocked(ctx, p); e != nil {
				t.Fatal(e)
			} // Warm only the independent metadata reader before the bounded action.
			var pendingProjection gateway.BrowserActivateTabResult
			if mode == "pending" {
				bounded, cancel := context.WithCancel(ctx)
				go func() {
					select {
					case <-fixture.pendingReady:
						cancel()
					case <-bounded.Done():
					}
				}()
				pending, pendingErr := client.CallTool(bounded, &schema.CallToolRequestParams{Name: "mechanize_browser_activate_tab", Arguments: args})
				cancel()
				if pendingErr != nil || pending == nil || pending.IsError != nil && *pending.IsError {
					t.Fatal("pending activation failed", pending, pendingErr)
				}
				body, _ := json.Marshal(pending.StructuredContent)
				var projected gateway.BrowserActivateTabResult
				if json.Unmarshal(body, &projected) != nil || projected.Outcome != "pending" || projected.Reason != "tabActivationPending" || projected.RunID == "" || projected.OperationID == "" {
					t.Fatal("pending lost truthful references", string(body))
				}
				pendingProjection = projected
				close(fixture.pending)
			}
			result := call(args)
			if result.IsError != nil && *result.IsError {
				t.Fatal("tracked origin activation failed", result)
			}
			raw, _ := json.Marshal(result.StructuredContent)
			var out gateway.BrowserActivateTabResult
			if json.Unmarshal(raw, &out) != nil {
				t.Fatal("result decode")
			}
			if mode == "pending" && (out.RunID != pendingProjection.RunID || out.OperationID != pendingProjection.OperationID) {
				t.Fatal("pending request changed durable references", out, pendingProjection)
			}
			if mode == "unsupported" {
				if out.Outcome != "notDispatched" || out.Reason != "unsupportedWorker" || out.RunID == "" || out.OperationID == "" || fixture.activations != 0 {
					t.Fatal("refusal lost references or exact closed reason", out)
				}
				repeated := call(args)
				body, _ := json.Marshal(repeated.StructuredContent)
				if string(body) != string(raw) || fixture.activations != 0 {
					t.Fatal("refusal replayed or changed references")
				}
				encoded, _ := json.Marshal(result)
				if strings.Contains(string(encoded), "PRIVATE_CANARY") {
					t.Fatal("refusal echoed private error")
				}
				return
			}
			if out.RunID == "" || out.OperationID == "" || fixture.activations != 1 {
				t.Fatal("activation not tracked exactly once", out, fixture.activations)
			}
			if unknown {
				if out.Outcome != "unknown" {
					t.Fatal("lost receipt claimed activated tab", out)
				}
			} else if out.Outcome != "activated" {
				t.Fatal("confirmed activation became avoidable unknown", out)
			}
			repeated := call(args)
			body, _ := json.Marshal(repeated.StructuredContent)
			if string(body) != string(raw) || fixture.activations != 1 {
				t.Fatal("repeated request activated a second tab", string(body))
			}
			state, e := store.StateGet(ctx, p, out.RunID)
			if e != nil {
				t.Fatal(e)
			}
			if unknown && len(state.UnresolvedEffects) != 1 || !unknown && (len(state.UnresolvedEffects) != 0 || len(state.Progress) != 1 || state.Progress[0].State == nil || *state.Progress[0].State != "verified") {
				t.Fatal("durable activation outcome mismatched receipt", state)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "PRIVATE_CANARY") || strings.Contains(string(encoded), "https://") {
				t.Fatal("result exposed URL/provider data")
			}
			if _, e = gate.AcquireExposureContext(ctx); !errors.Is(e, vault.ErrEntryProtected) {
				t.Fatal("activation released private protection")
			}
			for _, bad := range []map[string]any{{"sessionId": session.SessionID, "clientRequestId": "bad", "origin": "https://fixture.test/path"}, {"sessionId": session.SessionID, "clientRequestId": "bad", "origin": "https://fixture.test", "tabId": "existing-tab"}, {"sessionId": "foreign-session", "clientRequestId": "bad", "origin": "https://fixture.test", "tabHandle": "profile/browser/42"}} {
				r := call(bad)
				if r.IsError == nil || !*r.IsError || fixture.activations != 1 {
					t.Fatal("unapproved source/tab selection reached activation")
				}
			}
		})
	}
}

func TestActivateTabUnknownClosedReasonProjection(t *testing.T) {
	for _, code := range []string{"activationUnavailable", "receiptUnavailable", "authorityChanged", "PRIVATE-CANARY"} {
		e := activateTabFailure(&model.MechanizeError{Code: code, Message: "PRIVATE-CANARY", DispatchState: "unknown"}, "unknown")
		var result *model.MechanizeError
		expected := code
		if code == "PRIVATE-CANARY" {
			expected = "tabActivationUnavailable"
		}
		if !errors.As(e, &result) || result.Code != expected || result.DispatchState != "unknown" || strings.Contains(result.Message, "CANARY") {
			t.Fatal("unsafe or collapsed activation reason", e)
		}
	}
}
