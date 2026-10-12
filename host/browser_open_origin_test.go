package host

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/backend/chrome"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	automation "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/vault"
)

type openOriginFixture struct {
	t                 *testing.T
	observer          *durable.Builder
	prepares, creates int
	rejectReason      string
	refusals          int
	unknown           bool
	unsupported       bool
	tabs              []string
	foreground        int
}
type openOriginFixtureKey struct{}

func (f *openOriginFixture) PrepareOpenOrigin(ctx context.Context, p auth.Principal, origin string) (context.Context, int, error) {
	f.prepares++
	if f.unsupported {
		return nil, 0, &model.MechanizeError{Code: "unsupportedWorker", Message: "PRIVATE_CANARY", DispatchState: "notDispatched"}
	}
	if origin != "https://fixture.test" {
		return nil, 0, auth.ErrUnauthorized
	}
	return context.WithValue(ctx, openOriginFixtureKey{}, origin), 77, nil
}
func (f *openOriginFixture) ExecuteOpenOrigin(ctx context.Context, p auth.Principal, origin, attempt string, admit func(context.Context) error) (automation.StepResult, error) {
	fail := automation.StepResult{DispatchState: "notDispatched", VerificationState: "unknown"}
	if ctx.Value(openOriginFixtureKey{}) != origin || admit == nil || admit(ctx) != nil {
		return fail, auth.ErrUnauthorized
	}
	intent, e := data.RequireCommittedStepIntent(ctx, p)
	if e != nil || intent.LeaseEpoch != 77 || attempt != data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID) {
		f.t.Fatal("tab creation preceded committed bound intent", e)
	}
	// Independent authorized Datly reader must see the durable intent before creation.
	state, e := f.observer.StateGet(auth.WithPrincipal(context.Background(), p), p, intent.RunID)
	if e != nil || len(state.UnresolvedEffects) != 1 {
		f.t.Fatal("tab creation ran before actual commit/readback", e)
	}
	if f.rejectReason != "" {
		f.refusals++
		return fail, &model.MechanizeError{Code: f.rejectReason, Message: "PRIVATE_CANARY", DispatchState: "notDispatched"}
	}
	f.creates++
	f.tabs = append(f.tabs, origin+"/")
	if f.unknown {
		return automation.StepResult{DispatchState: "unknown", VerificationState: "unknown"}, errors.New("PRIVATE_CANARY lost response")
	}
	value := model.Value{Kind: model.StringValue, String: "profile/browser/42"}
	return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified", Value: &value}, nil
}
func TestOpenOriginHostMCPDurableCreationAndUnknownNeverReplay(t *testing.T) {
	for _, mode := range []string{"created", "unknown", "unsupported", "permissionUnavailable", "windowUnavailable", "controller-created", "controller-unknown"} {
		t.Run(mode, func(t *testing.T) {
			unknown := mode == "unknown" || mode == "controller-unknown"
			controller := strings.HasPrefix(mode, "controller-")
			p, _ := auth.NewPrincipal("fixture", "", "origin-owner", []string{"desktop:control", "desktop:observe", "consent:admin"})
			p.ClientID = "origin-client"
			if controller {
				p.ClientID = "controller:origin-client"
			}
			p.ClientName = "Origin client"
			ctx := auth.WithPrincipal(context.Background(), p)
			_, file, _, _ := runtime.Caller(0)
			source := filepath.Dir(filepath.Dir(file))
			storage := t.TempDir()
			gate, _ := vault.NewGuardedExposureGate(func(context.Context) error { return vault.ErrEntryProtected })
			initialTabs := []string{"https://draft.fixture.test/review", "chrome://extensions"}
			fixture := &openOriginFixture{t: t, unknown: unknown, unsupported: mode == "unsupported", tabs: append([]string(nil), initialTabs...), foreground: 0}
			if mode == "permissionUnavailable" || mode == "windowUnavailable" {
				fixture.rejectReason = mode
			}
			h := &Host{users: map[string]User{p.Namespace: {Subject: p.Subject, WebOrigins: []string{"https://fixture.test"}}}, vaultExposure: gate, openOriginFixture: fixture}
			noNative := func(context.Context, auth.Principal) (int, error) {
				t.Fatal("origin opening borrowed native/renderer lease")
				return 0, nil
			}
			store, e := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: noNative, PrepareStepAuthority: h.prepareStepExecutor}, h.execute)
			if e != nil {
				t.Fatal(e)
			}
			h.durable = store
			defer store.Close(context.Background())
			observer, e := durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: noNative}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
				t.Fatal("observer dispatched")
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
			session, e := rt.Open(ctx, "Open origin fixture")
			if e != nil {
				t.Fatal(e)
			}
			defer rt.Close(ctx, session.SessionID)
			options := ConsentBrokerOptions{Invoke: store.InvokePrivateComponent, Enrolled: h.enrolled, SessionOwned: rt.CheckSession, Policy: h.ConsentPolicy}
			if controller {
				options.ControllerPolicy = func(c context.Context, actor auth.Principal) (context.Context, time.Time, func(), error) {
					if actor.ClientID != p.ClientID || auth.NativeHuman(c) {
						return nil, time.Time{}, nil, auth.ErrUnauthorized
					}
					expiry := time.Now().Add(time.Minute)
					bound, cancel := context.WithDeadline(c, expiry)
					return bound, expiry, cancel, nil
				}
			}
			h.consent, e = NewConsentBroker(options)
			if e != nil {
				t.Fatal(e)
			}
			server, e := gateway.New(gateway.Dependencies{Runtime: rt, Policy: func(context.Context, auth.Principal) (script.Policy, error) { return script.Policy{}, nil }, BrowserOpenOrigin: h.BrowserOpenOrigin})
			if e != nil {
				t.Fatal(e)
			}
			client := server.AsClient(ctx)
			if _, e = client.Initialize(ctx); e != nil {
				t.Fatal(e)
			}
			var dispatcher *gateway.ControllerDispatcher
			controllerID := chrome.ControllerIdentity{Principal: p, ConversationID: "origin-connection", Origin: "https://controller.fixture.test", DocumentID: "controller-document"}
			if controller {
				dispatcher, e = gateway.NewControllerDispatcher(server, rt)
				if e != nil {
					t.Fatal(e)
				}
				defer dispatcher.CloseController(ctx, controllerID)
				catalog, e := dispatcher.ListTools(ctx, controllerID)
				if e != nil {
					t.Fatal(e)
				}
				found := false
				for _, tool := range catalog.Tools {
					if tool.Name == "mechanize_browser_open_origin" {
						raw, _ := json.Marshal(tool.InputSchema)
						var input map[string]any
						_ = json.Unmarshal(raw, &input)
						if input["type"] != "object" || input["additionalProperties"] != false {
							t.Fatal("canonical input schema changed")
						}
						found = true
					}
				}
				if !found {
					t.Fatal("opener missing from controller catalog")
				}
				opened, e := dispatcher.CallTool(ctx, controllerID, chrome.ControllerToolCall{Name: "mechanize_session_open", Arguments: json.RawMessage(`{"name":"origin controller"}`)})
				if e != nil {
					t.Fatal(e)
				}
				raw, _ := json.Marshal(opened.StructuredContent)
				var openedSession gateway.SessionRef
				_ = json.Unmarshal(raw, &openedSession)
				session.SessionID = openedSession.SessionID
			}
			args := map[string]any{"sessionId": session.SessionID, "clientRequestId": "one-explicit-open", "origin": "https://fixture.test"}
			call := func(a map[string]any) *schema.CallToolResult {
				var out *schema.CallToolResult
				var e error
				if controller {
					raw, _ := json.Marshal(a)
					out, e = dispatcher.CallTool(ctx, controllerID, chrome.ControllerToolCall{Name: "mechanize_browser_open_origin", Arguments: raw})
				} else {
					out, e = client.CallTool(ctx, &schema.CallToolRequestParams{Name: "mechanize_browser_open_origin", Arguments: a})
				}
				if e != nil {
					t.Fatal(e)
				}
				return out
			}
			if !controller {
				denied := call(args)
				if denied.IsError == nil || !*denied.IsError || fixture.prepares != 0 || fixture.creates != 0 {
					t.Fatal("opening bypassed current Control consent")
				}
				bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: session.SessionID, Purpose: "Open approved website in a new background tab"})
				request, e := h.consent.Request(bound, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "origin", Origin: "https://fixture.test"}, Modes: []consent.Mode{consent.Control}, Purpose: "Open approved website in a new background tab", DurationSeconds: 120})
				if e != nil {
					t.Fatal(e)
				}
				human, _ := auth.WithNativeHuman(bound)
				decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
				if _, e = h.consent.NativeRPC(human, "decide", decision); e != nil {
					t.Fatal(e)
				}
			}
			if _, e = observer.CredentialDeliveryBlocked(ctx, p); e != nil {
				t.Fatal(e)
			} // Warm only the independent metadata reader before the bounded action.
			result := call(args)
			if result.IsError != nil && *result.IsError {
				t.Fatal("tracked origin opening failed", result)
			}
			raw, _ := json.Marshal(result.StructuredContent)
			var out gateway.BrowserOpenOriginResult
			if json.Unmarshal(raw, &out) != nil {
				t.Fatal("result decode")
			}
			if fixture.rejectReason != "" {
				if out.Outcome != "notDispatched" || out.Reason != fixture.rejectReason || out.TabHandle != "" || fixture.creates != 0 || fixture.refusals != 1 {
					t.Fatal("closed native refusal lost", out)
				}
				repeated := call(args)
				body, _ := json.Marshal(repeated.StructuredContent)
				if string(body) != string(raw) || fixture.refusals != 1 || fixture.creates != 0 {
					t.Fatal("negative receipt replayed or changed")
				}
				encoded, _ := json.Marshal(result)
				if strings.Contains(string(encoded), "PRIVATE_CANARY") {
					t.Fatal("private refusal payload escaped")
				}
				state, e := store.StateGet(ctx, p, out.RunID)
				if e != nil || len(state.UnresolvedEffects) != 0 {
					t.Fatal("not-dispatched refusal became unresolved", e)
				}
				return
			}
			if mode == "unsupported" {
				if out.Outcome != "notDispatched" || out.Reason != "unsupportedWorker" || out.TabHandle != "" || out.RunID == "" || out.OperationID == "" || fixture.creates != 0 {
					t.Fatal("refusal lost references or exact closed reason", out)
				}
				repeated := call(args)
				body, _ := json.Marshal(repeated.StructuredContent)
				if string(body) != string(raw) || fixture.creates != 0 {
					t.Fatal("refusal replayed or changed references")
				}
				encoded, _ := json.Marshal(result)
				if strings.Contains(string(encoded), "PRIVATE_CANARY") {
					t.Fatal("refusal echoed private error")
				}
				return
			}
			if !reflect.DeepEqual(fixture.tabs[:2], initialTabs) || len(fixture.tabs) != 3 || fixture.foreground != 0 {
				t.Fatal("opening altered existing tabs or foreground")
			}
			if out.RunID == "" || out.OperationID == "" || fixture.creates != 1 {
				t.Fatal("creation not tracked exactly once", out, fixture.creates)
			}
			if unknown {
				if out.Outcome != "unknown" || out.TabHandle != "" {
					t.Fatal("lost receipt claimed created tab", out)
				}
			} else if out.Outcome != "created" || out.TabHandle != "profile/browser/42" {
				t.Fatal("confirmed creation became avoidable unknown", out)
			}
			repeated := call(args)
			body, _ := json.Marshal(repeated.StructuredContent)
			if string(body) != string(raw) || fixture.creates != 1 {
				t.Fatal("repeated request created a second tab", string(body))
			}
			state, e := store.StateGet(ctx, p, out.RunID)
			if e != nil {
				t.Fatal(e)
			}
			if unknown && len(state.UnresolvedEffects) != 1 || !unknown && (len(state.UnresolvedEffects) != 0 || len(state.Progress) != 1 || state.Progress[0].State == nil || *state.Progress[0].State != "verified") {
				t.Fatal("durable creation outcome mismatched receipt", state)
			}
			encoded, _ := json.Marshal(result)
			if strings.Contains(string(encoded), "PRIVATE_CANARY") || strings.Contains(string(encoded), "https://") {
				t.Fatal("result exposed URL/provider data")
			}
			if _, e = gate.AcquireExposureContext(ctx); !errors.Is(e, vault.ErrEntryProtected) {
				t.Fatal("opening released private protection")
			}
			for _, bad := range []map[string]any{{"sessionId": session.SessionID, "clientRequestId": "bad", "origin": "https://fixture.test/path"}, {"sessionId": session.SessionID, "clientRequestId": "bad", "origin": "https://fixture.test", "tabId": "existing-tab"}, {"sessionId": "foreign-session", "clientRequestId": "bad", "origin": "https://fixture.test"}, {"sessionId": session.SessionID, "clientRequestId": "forbidden-origin", "origin": "https://unauthorized.fixture.test"}} {
				r := call(bad)
				if r.IsError == nil || !*r.IsError || fixture.creates != 1 {
					t.Fatal("unapproved source/tab selection reached opening")
				}
			}
		})
	}
}
