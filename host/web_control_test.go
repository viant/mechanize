package host

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/session"
)

type webControlFixture struct {
	manager                                                                      *WebControlManager
	owner                                                                        context.Context
	cancel                                                                       context.CancelFunc
	principal                                                                    auth.Principal
	ctx                                                                          context.Context
	step                                                                         model.Step
	ready                                                                        WebControlReadiness
	enrollment                                                                   WebControlScope
	dispatches, qualifications, verifications, authorizations, releases, records int
	verifyErr, consentErr, dispatchErr, retireErr                                error
	cleanup                                                                      WebControlCleanup
	dispatchedResult                                                             automation.StepResult
}

func newWebControlFixture(t *testing.T) *webControlFixture {
	t.Helper()
	f := &webControlFixture{}
	f.principal, _ = auth.NewPrincipal("fixture:issuer", "tenant", "web-owner", []string{"desktop:control"})
	f.principal.ClientID = "verified-client"
	f.ctx = auth.WithPrincipal(context.Background(), f.principal)
	f.ctx = auth.WithConsentBinding(f.ctx, auth.ConsentBinding{GrantID: "exact-grant", SessionID: "client-session", Purpose: "fixture purpose"})
	f.owner, f.cancel = context.WithCancel(context.Background())
	t.Cleanup(f.cancel)
	plan, err := script.Compile(`web.tab(origin: "https://fixture.test").getById("save", exact: true).click()`)
	if err != nil {
		t.Fatal(err)
	}
	f.step = plan.Steps[0]
	extension := "chrome-extension://" + strings.Repeat("a", 32) + "/"
	f.enrollment = WebControlScope{Profiles: []WebControlProfile{{ProfileChannel: "enrolled-profile", BrowserInstance: "chrome-instance", ExtensionOrigin: extension, Origins: []string{"https://fixture.test"}}}}
	f.ready = WebControlReadiness{Authority: WebControlAuthority{Owner: f.principal.Namespace, ExtensionOrigin: extension, ID: "renderer-authority", Generation: 7, BrokerEpoch: "broker-generation", ChannelEpoch: "signed-channel-generation", ScopeHash: "operator-scope-hash", NativeHost: session.ProcessIdentity{PID: 1001, UID: uint32(os.Getuid()), Executable: "/fixture/signed-native-host", StartToken: "host-start"}, BrowserParent: session.ProcessIdentity{PID: 1000, UID: uint32(os.Getuid()), Executable: "/fixture/Google Chrome", StartToken: "chrome-start"}, Document: chrome.Document{Identity: chrome.Identity{ProfileChannel: "enrolled-profile", BrowserInstance: "chrome-instance", TabID: 11, FrameID: 0, DocumentID: "live-document", Generation: 3}, Origin: "https://fixture.test"}}, NativeHostSignatureQualified: true, KernelPeerQualified: true, ChromeParentQualified: true, ProfileQualified: true, ExtensionQualified: true, DocumentQualified: true, ExecutorQualified: true, Actions: []string{"element.press", "element.fill"}, Locators: []string{"role", "id", "testId", "label"}}
	f.cleanup = WebControlCleanup{AuthorityRetired: true, ExecutorsQuiesced: true}
	f.dispatchedResult = automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}
	f.manager, err = NewWebControlManager(WebControlOptions{
		Owner:    f.owner,
		Enrolled: func(context.Context, auth.Principal) (WebControlScope, error) { return f.enrollment, nil },
		Qualify: func(context.Context, auth.Principal, model.Surface) (WebControlReadiness, error) {
			f.qualifications++
			r := f.ready
			if r.ValidUntil.IsZero() {
				r.ValidUntil = time.Now().Add(time.Second)
			}
			return r, nil
		},
		VerifyChannel: func(context.Context, auth.Principal, WebControlAuthority) error {
			f.verifications++
			return f.verifyErr
		},
		Authorize: func(ctx context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
			f.authorizations++
			if f.consentErr != nil {
				return nil, f.consentErr
			}
			return &consent.Lease{Context: ctx, Release: func() { f.releases++ }}, nil
		},
		ExecutePinned: func(_ context.Context, p auth.Principal, s model.Step, _ map[string]model.Value, a WebControlAuthority) (automation.StepResult, error) {
			f.dispatches++
			if p.Namespace != f.principal.Namespace || a != f.ready.Authority {
				t.Error("provider received unpinned actor/channel")
			}
			return f.dispatchedResult, f.dispatchErr
		},
		Retire: func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
			return f.cleanup, f.retireErr
		},
		RecordCleanupUnknown: func(context.Context, auth.Principal, WebControlAuthority) error { f.records++; return nil },
		Close:                func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// A real Endly callback supplies the unforgeable execution metadata. No employee
// browser is connected and no input is sent; data scope simulates post-commit
// dispatcher admission. Root durable integration tests prove the actual commit.
func withWebExecution(t *testing.T, f *webControlFixture, body func(context.Context, auth.Principal, model.Step)) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	runtime, err := automation.New(func(ctx context.Context, p auth.Principal, s model.Step, _ map[string]model.Value) (automation.StepResult, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		body(ctx, p, s)
		return automation.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := runtime.Open(f.ctx, "web-fixture")
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close(f.ctx, opened.SessionID)
	operation, err := runtime.StartPlan(f.ctx, opened.SessionID, model.Plan{SchemaVersion: 1, Steps: []model.Step{f.step}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	if _, err = runtime.Wait(deadline, opened.SessionID, operation.ID); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("Endly assertion callback count=%d", calls)
	}
}
func prepareWeb(t *testing.T, f *webControlFixture, ctx context.Context, p auth.Principal, step model.Step) context.Context {
	t.Helper()
	prepared, epoch, err := f.manager.Prepare(ctx, p, step)
	if err != nil {
		t.Error(err)
		return ctx
	}
	if epoch != 7 {
		t.Errorf("renderer epoch=%d", epoch)
	}
	scoped, err := data.WithScope(prepared, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
	if err != nil {
		t.Error(err)
		return ctx
	}
	return scoped
}
func TestWebControlClosedDefaultAndFreshIndependentCapabilities(t *testing.T) {
	if _, err := NewWebControlManager(WebControlOptions{}); !errors.Is(err, ErrWebControlUnqualified) {
		t.Fatal(err)
	}
	f := newWebControlFixture(t)
	caps := f.manager.Capabilities(f.ctx, f.principal)
	if !caps["web:semanticPress"] || !caps["web:replaceValue"] || caps["native:semanticPress"] {
		t.Fatalf("renderer capabilities: %+v", caps)
	}
	f.ready.KernelPeerQualified = false
	if len(f.manager.Capabilities(f.ctx, f.principal)) != 0 {
		t.Fatal("unsigned peer retained mutation capability")
	}
}
func TestWebControlFreshQualificationAndDurableIntentBeforeDispatch(t *testing.T) {
	f := newWebControlFixture(t)
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared, epoch, err := f.manager.Prepare(ctx, p, step)
		if err != nil {
			t.Error(err)
			return
		}
		if epoch != 7 || f.dispatches != 0 {
			t.Error("pre-intent admission dispatched input or borrowed desktop epoch")
		}
		result, err := f.manager.Execute(prepared, p, step, nil)
		if !errors.Is(err, ErrWebControlIntent) || result.DispatchState != "notDispatched" {
			t.Errorf("missing commit scope: %+v %v", result, err)
		}
		scoped, _ := data.WithScope(prepared, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
		result, err = f.manager.Execute(scoped, p, step, nil)
		if err != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" {
			t.Errorf("dispatch: %+v %v", result, err)
		}
		if f.qualifications != 2 || f.verifications != 3 || f.authorizations != 1 || f.releases != 1 {
			t.Errorf("fresh admission/retirement checks omitted: %+v", f)
		}
		_, err = f.manager.Execute(scoped, p, step, nil)
		if !errors.Is(err, ErrWebControlIntent) || f.dispatches != 1 {
			t.Error("single-use durable intent replayed")
		}
	})
}
func TestWebControlScopeAndQualificationDenials(t *testing.T) {
	cases := []struct {
		name   string
		change func(*webControlFixture)
	}{
		{"native host signature", func(f *webControlFixture) { f.ready.NativeHostSignatureQualified = false }},
		{"missing action evidence", func(f *webControlFixture) { f.ready.Actions = nil }},
		{"missing locator evidence", func(f *webControlFixture) { f.ready.Locators = nil }},
		{"Chrome parent", func(f *webControlFixture) { f.ready.ChromeParentQualified = false }},
		{"profile", func(f *webControlFixture) { f.ready.ProfileQualified = false }},
		{"extension", func(f *webControlFixture) { f.ready.ExtensionQualified = false }},
		{"document", func(f *webControlFixture) { f.ready.DocumentQualified = false }},
		{"executor", func(f *webControlFixture) { f.ready.ExecutorQualified = false }},
		{"unresolved executor", func(f *webControlFixture) { f.ready.UnresolvedExecutors = true }},
		{"expired", func(f *webControlFixture) { f.ready.ValidUntil = time.Now().Add(-time.Second) }},
		{"overlong freshness", func(f *webControlFixture) { f.ready.ValidUntil = time.Now().Add(time.Minute) }},
		{"cross owner", func(f *webControlFixture) { f.ready.Authority.Owner = "other-owner" }},
		{"wrong origin", func(f *webControlFixture) { f.ready.Authority.Document.Origin = "https://other.test" }},
		{"wrong profile", func(f *webControlFixture) { f.ready.Authority.Document.ProfileChannel = "other-profile" }},
		{"wrong extension", func(f *webControlFixture) {
			f.ready.Authority.ExtensionOrigin = "chrome-extension://" + strings.Repeat("b", 32) + "/"
		}},
		{"nonroot frame", func(f *webControlFixture) { f.ready.Authority.Document.FrameID = 1 }},
		{"zero document generation", func(f *webControlFixture) { f.ready.Authority.Document.Generation = 0 }},
		{"audit verifier", func(f *webControlFixture) { f.verifyErr = errors.New("audit peer mismatch") }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			f := newWebControlFixture(t)
			tt.change(f)
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				if _, _, err := f.manager.Prepare(ctx, p, step); err == nil {
					t.Error("unqualified renderer admitted")
				}
				if f.dispatches != 0 {
					t.Error("qualification denial dispatched")
				}
			})
		})
	}
}
func TestWebControlIntentCannotCrossStepOwnerClientGrantEpochOrDocument(t *testing.T) {
	for _, name := range []string{"step", "owner", "client", "grant", "epoch", "document", "channel", "run"} {
		t.Run(name, func(t *testing.T) {
			f := newWebControlFixture(t)
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				scoped := prepareWeb(t, f, ctx, p, step)
				switch name {
				case "step":
					step.Target.Locator.Value.String = "other-element"
				case "owner":
					p, _ = auth.NewPrincipal("fixture:issuer", "tenant", "other", []string{"desktop:control"})
					scoped = auth.WithPrincipal(scoped, p)
				case "client":
					p.ClientID = "other-client"
					scoped = auth.WithPrincipal(scoped, p)
				case "grant":
					scoped = auth.WithConsentBinding(scoped, auth.ConsentBinding{GrantID: "other-grant", SessionID: "client-session", Purpose: "fixture purpose"})
				case "epoch":
					scoped, _ = data.WithScope(scoped, data.Scope{Namespace: p.Namespace, LeaseEpoch: 8})
				case "document":
					f.ready.Authority.Document.DocumentID = "replacement-document"
				case "channel":
					f.ready.Authority.ChannelEpoch = "reconnected-channel"
				case "run":
					scoped.Value(webControlIntentKey{}).(*webControlIntent).metadata.RunID = "other-run"
				}
				if _, err := f.manager.Execute(scoped, p, step, nil); err == nil {
					t.Error("lent intent admitted")
				}
				if f.dispatches != 0 {
					t.Error("cross-authority mutation dispatched")
				}
			})
		})
	}
}
func TestWebControlPerStepConsentAndUnknownRetirementBarrier(t *testing.T) {
	t.Run("consent denial", func(t *testing.T) {
		f := newWebControlFixture(t)
		f.consentErr = auth.ErrUnauthorized
		withWebExecution(t, f, func(ctx context.Context, p auth.Principal, s model.Step) {
			ctx = prepareWeb(t, f, ctx, p, s)
			if _, err := f.manager.Execute(ctx, p, s, nil); !errors.Is(err, auth.ErrUnauthorized) {
				t.Error(err)
			}
			if f.dispatches != 0 {
				t.Error("mutation without per-step consent")
			}
		})
	})
	t.Run("unknown retire persisted", func(t *testing.T) {
		f := newWebControlFixture(t)
		f.cleanup.UnknownExecutors = true
		withWebExecution(t, f, func(ctx context.Context, p auth.Principal, s model.Step) {
			ctx = prepareWeb(t, f, ctx, p, s)
			result, err := f.manager.Execute(ctx, p, s, nil)
			if !errors.Is(err, ErrWebControlCleanupUnknown) || result.VerificationState != "unknown" || f.records != 1 || f.releases != 0 {
				t.Errorf("false cleanup proof: %+v %v records=%d releases=%d", result, err, f.records, f.releases)
			}
			if _, _, err = f.manager.Prepare(ctx, p, s); !errors.Is(err, ErrWebControlCleanupUnknown) {
				t.Error("unknown renderer cleanup did not inhibit next intent")
			}
		})
	})
	t.Run("interrupted outcome never verified", func(t *testing.T) {
		f := newWebControlFixture(t)
		f.dispatchErr = context.Canceled
		f.dispatchedResult = automation.StepResult{DispatchState: "notDispatched", VerificationState: "verified"}
		withWebExecution(t, f, func(ctx context.Context, p auth.Principal, s model.Step) {
			ctx = prepareWeb(t, f, ctx, p, s)
			result, err := f.manager.Execute(ctx, p, s, nil)
			if !errors.Is(err, context.Canceled) || result.DispatchState != "unknown" || result.VerificationState != "unknown" {
				t.Errorf("false clean interrupted outcome: %+v %v", result, err)
			}
		})
	})
}

func TestHostWebMutationPolicyDoesNotDependOnNativeLease(t *testing.T) {
	f := newWebControlFixture(t)
	h := &Host{webControl: f.manager, users: map[string]User{f.principal.Namespace: {WebOrigins: []string{"https://fixture.test"}}}}
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || !policy.AllowMutation || !policy.Capabilities["web:semanticPress"] || policy.Capabilities["native:semanticPress"] {
		t.Fatalf("independent web authority: %+v %v", policy, err)
	}
	if err := (script.Validator{}).CheckStepPolicy(f.step, policy); err != nil {
		t.Fatalf("qualified web step cannot compile: %v", err)
	}
	f.ready.ChromeParentQualified = false
	policy, err = h.Policy(f.ctx, f.principal)
	if err != nil || policy.AllowMutation || policy.Capabilities["web:semanticPress"] {
		t.Fatalf("unqualified live connection exposed input: %+v %v", policy, err)
	}
}

func TestWebControlOwnerCancellationAndClosedLifecycle(t *testing.T) {
	f := newWebControlFixture(t)
	f.manager.options.ExecutePinned = func(ctx context.Context, _ auth.Principal, _ model.Step, _ map[string]model.Value, _ WebControlAuthority) (automation.StepResult, error) {
		f.dispatches++
		f.cancel()
		<-ctx.Done()
		return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, ctx.Err()
	}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, s model.Step) {
		ctx = prepareWeb(t, f, ctx, p, s)
		result, err := f.manager.Execute(ctx, p, s, nil)
		if !errors.Is(err, context.Canceled) || result.DispatchState != "unknown" || result.VerificationState != "unknown" {
			t.Errorf("owner cancellation falsely clean: %+v %v", result, err)
		}
		if len(f.manager.Capabilities(ctx, p)) != 0 {
			t.Error("terminated owner kept renderer input capabilities")
		}
	})
	closed := newWebControlFixture(t)
	closedCount := 0
	closed.manager.options.Close = func(context.Context) error { closedCount++; return nil }
	if err := closed.manager.Close(context.Background()); err != nil || closedCount != 1 {
		t.Errorf("channel lifecycle close: %v", err)
	}
	if len(closed.manager.Capabilities(closed.ctx, closed.principal)) != 0 {
		t.Error("closed channel remained qualified")
	}
}

func TestWebControlExactAuthorityRetirementEvidenceIsDistinctFromDocumentShutdown(t *testing.T) {
	f := newWebControlFixture(t)
	f.cleanup = WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		result, err := f.manager.Execute(prepared, p, step, nil)
		if err != nil || result.DispatchState != "dispatched" || f.releases != 1 {
			t.Errorf("confirmed exact authority retirement: result=%+v err=%v releases=%d", result, err, f.releases)
		}
	})
	f2 := newWebControlFixture(t)
	f2.cleanup = WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true, UnknownExecutors: true}
	withWebExecution(t, f2, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f2, ctx, p, step)
		_, err := f2.manager.Execute(prepared, p, step, nil)
		if !errors.Is(err, ErrWebControlCleanupUnknown) || f2.releases != 0 || f2.records != 1 {
			t.Errorf("unknown lease retirement falsely released consent: err=%v releases=%d records=%d", err, f2.releases, f2.records)
		}
	})
}
