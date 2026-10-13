package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
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
	manager                                                             *WebControlManager
	owner                                                               context.Context
	cancel                                                              context.CancelFunc
	principal                                                           auth.Principal
	ctx                                                                 context.Context
	step                                                                model.Step
	ready                                                               WebControlReadiness
	enrollment                                                          WebControlScope
	dispatches, qualifications, verifications, authorizations, releases int
	verifyErr, consentErr, dispatchErr, retireErr                       error
	cleanup                                                             WebControlCleanup
	dispatchedResult                                                    automation.StepResult
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
	f.ready = WebControlReadiness{NewlyAcquired: true, Authority: WebControlAuthority{Owner: f.principal.Namespace, ExtensionOrigin: extension, ID: "renderer-authority", Generation: 7, BrokerEpoch: "broker-generation", ChannelEpoch: "signed-channel-generation", ScopeHash: "operator-scope-hash", NativeHost: session.ProcessIdentity{PID: 1001, UID: uint32(os.Getuid()), Executable: "/fixture/signed-native-host", StartToken: "host-start"}, BrowserParent: session.ProcessIdentity{PID: 1000, UID: uint32(os.Getuid()), Executable: "/fixture/Google Chrome", StartToken: "chrome-start"}, Document: chrome.Document{Identity: chrome.Identity{ProfileChannel: "enrolled-profile", BrowserInstance: "chrome-instance", TabID: 11, FrameID: 0, DocumentID: "live-document", Generation: 3}, Origin: "https://fixture.test"}}, NativeHostSignatureQualified: true, KernelPeerQualified: true, ChromeParentQualified: true, ProfileQualified: true, ExtensionQualified: true, DocumentQualified: true, ExecutorQualified: true, Actions: []string{"element.press", "element.fill"}, Locators: []string{"role", "id", "testId", "label"}}
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
		VerifyChannel: func(_ context.Context, _ auth.Principal, a WebControlAuthority) error {
			f.verifications++
			if a != f.ready.Authority {
				return errors.New("fixture pinned channel changed")
			}
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
		Close: func(context.Context) error { return nil },
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
		if f.qualifications != 1 || f.verifications != 3 || f.authorizations != 1 || f.releases != 1 {
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
	t.Run("unknown retire retained", func(t *testing.T) {
		f := newWebControlFixture(t)
		f.cleanup.UnknownExecutors = true
		withWebExecution(t, f, func(ctx context.Context, p auth.Principal, s model.Step) {
			ctx = prepareWeb(t, f, ctx, p, s)
			result, err := f.manager.Execute(ctx, p, s, nil)
			if !errors.Is(err, ErrWebControlCleanupUnknown) || result.VerificationState != "unknown" || f.releases != 0 {
				t.Errorf("false cleanup proof: %+v %v releases=%d", result, err, f.releases)
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

func TestWebControlCancellationPreservesConfirmedTransportAbsence(t *testing.T) {
	for _, confirmed := range []bool{true, false} {
		t.Run(fmt.Sprint(confirmed), func(t *testing.T) {
			f := newWebControlFixture(t)
			var cancelDispatch context.CancelFunc
			f.manager.options.ExecutePinned = func(context.Context, auth.Principal, model.Step, map[string]model.Value, WebControlAuthority) (automation.StepResult, error) {
				cancelDispatch()
				if confirmed {
					return automation.StepResult{DispatchState: "notDispatched"}, &model.MechanizeError{Code: "dispatchGateCancelled", DispatchState: "notDispatched"}
				}
				return automation.StepResult{DispatchState: "notDispatched"}, context.Canceled
			}
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				prepared, cancelDispatch = context.WithCancel(prepared)
				defer cancelDispatch()
				result, err := f.manager.Execute(prepared, p, step, nil)
				want := "unknown"
				if confirmed {
					want = "notDispatched"
				}
				if err == nil || result.DispatchState != want || result.VerificationState != "unknown" || f.releases != 1 {
					t.Errorf("cancellation lost transport evidence: result=%+v err=%v releases=%d", result, err, f.releases)
				}
			})
		})
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
		if !errors.Is(err, ErrWebControlCleanupUnknown) || f2.releases != 0 {
			t.Errorf("unknown lease retirement falsely released consent: err=%v releases=%d", err, f2.releases)
		}
	})
}

func TestWebControlFailedPinnedRevalidationRetiresOnlyOriginalIntent(t *testing.T) {
	for _, mode := range []string{"retired", "otherAuthority", "unknownCleanup", "foreignIntent"} {
		t.Run(mode, func(t *testing.T) {
			f := newWebControlFixture(t)
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				original := f.ready.Authority
				rejected := errors.New("staleGeneration fixture")
				f.verifyErr = rejected
				retired := 0
				f.manager.options.Retire = func(_ context.Context, actual auth.Principal, a WebControlAuthority) (WebControlCleanup, error) {
					retired++
					if (a != original && a != f.ready.Authority) || actual.Namespace != p.Namespace || actual.ClientID != p.ClientID {
						t.Error("retirement borrowed another authority")
					}
					if mode == "otherAuthority" {
						return WebControlCleanup{}, errors.New("exact lease replaced")
					}
					if mode == "unknownCleanup" {
						return WebControlCleanup{UnknownExecutors: true}, nil
					}
					return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
				}
				if mode == "foreignIntent" {
					prepared = auth.WithConsentBinding(prepared, auth.ConsentBinding{GrantID: "foreign", SessionID: "foreign", Purpose: "foreign"})
				}
				result, e := f.manager.Execute(prepared, p, step, nil)
				if result.DispatchState != "notDispatched" || e == nil || f.dispatches != 0 {
					t.Fatal("failed pre-input qualification lost state", e)
				}
				if mode == "foreignIntent" {
					if retired != 0 {
						t.Fatal("foreign intent retired authority")
					}
					return
				}
				if retired != 1 {
					t.Fatal("own pin not retired exactly once")
				}
				if mode != "retired" {
					if !errors.Is(e, ErrWebControlCleanupUnknown) {
						t.Fatal("uncertain cleanup unblocked", e)
					}
					return
				}
				if !errors.Is(e, rejected) {
					t.Fatal("known rejection became uncertainty", e)
				}
				if _, e = f.manager.Execute(prepared, p, step, nil); !errors.Is(e, ErrWebControlIntent) || retired != 1 {
					t.Fatal("consumed original intent replayed", e)
				}
				f.verifyErr = nil
				f.ready.Authority.Generation++
				f.manager.options.Qualify = func(context.Context, auth.Principal, model.Surface) (WebControlReadiness, error) {
					r := f.ready
					r.ValidUntil = time.Now().Add(time.Second)
					return r, nil
				}
				if _, epoch, e := f.manager.Prepare(ctx, p, step); e != nil || epoch != 8 {
					t.Fatal("next fresh preparation stranded", epoch, e)
				}
			})
		})
	}
}

func TestWebControlAllOwnedPreDispatchFailuresAbandonOriginalPin(t *testing.T) {
	for _, mode := range []string{"consentError", "nilLease", "nilLeaseContext", "foreignLeaseBinding", "verifyChannel", "navigationArguments", "navigationOrigin", "navigationDestination", "cancelBeforeDispatch"} {
		t.Run(mode, func(t *testing.T) {
			f := newWebControlFixture(t)
			if strings.HasPrefix(mode, "navigation") {
				f.step.Action = "browser.navigate"
				f.step.Target.Locator = nil
				f.step.Arguments = map[string]model.Value{"url": {Kind: model.ReferenceValue, Ref: "input.url", Expected: model.StringValue}}
				f.ready.Actions = append(f.ready.Actions, "browser.navigate")
			}
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				original := f.ready.Authority
				intent := prepared.Value(webControlIntentKey{}).(*webControlIntent)
				retired := 0
				f.manager.options.Retire = func(_ context.Context, p auth.Principal, a WebControlAuthority) (WebControlCleanup, error) {
					retired++
					if a != original {
						t.Error("wrong pin retired")
					}
					return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
				}
				values := map[string]model.Value{"input.url": {Kind: model.StringValue, String: "https://other.test/path"}}
				switch mode {
				case "authorityMismatch":
					f.ready.Authority.Generation++
				case "actionUnavailable":
					f.ready.Actions = nil
				case "consentError":
					f.consentErr = errors.New("refused")
				case "nilLease":
					f.manager.options.Authorize = func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error) { return nil, nil }
				case "nilLeaseContext":
					f.manager.options.Authorize = func(context.Context, auth.Principal, model.Surface) (*consent.Lease, error) {
						return &consent.Lease{Release: func() {}}, nil
					}
				case "foreignLeaseBinding":
					f.manager.options.Authorize = func(c context.Context, _ auth.Principal, _ model.Surface) (*consent.Lease, error) {
						return &consent.Lease{Context: auth.WithConsentBinding(c, auth.ConsentBinding{}), Release: func() {}}, nil
					}
				case "verifyChannel":
					f.manager.options.VerifyChannel = func(context.Context, auth.Principal, WebControlAuthority) error {
						f.verifications++
						if f.verifications >= 3 {
							return errors.New("channel drift")
						}
						return nil
					}
				case "navigationArguments":
					values = nil
				case "navigationOrigin":
					values["input.url"] = model.Value{Kind: model.StringValue, String: "file:///fixture"}
				case "navigationDestination":
					f.manager.options.Authorize = func(c context.Context, _ auth.Principal, s model.Surface) (*consent.Lease, error) {
						if s.Origin != step.Target.Surface.Origin {
							return nil, auth.ErrUnauthorized
						}
						return &consent.Lease{Context: c, Release: func() {}}, nil
					}
				case "cancelBeforeDispatch":
					var stop context.CancelFunc
					f.manager.options.Authorize = func(c context.Context, _ auth.Principal, _ model.Surface) (*consent.Lease, error) {
						child, cancel := context.WithCancel(c)
						stop = cancel
						return &consent.Lease{Context: child, Release: func() {}}, nil
					}
					f.manager.options.VerifyChannel = func(context.Context, auth.Principal, WebControlAuthority) error {
						if stop != nil {
							stop()
						}
						return nil
					}
				}
				result, e := f.manager.Execute(prepared, p, step, values)
				if e == nil || result.DispatchState != "notDispatched" || f.dispatches != 0 || retired != 1 || !intent.consumed || intent.dispatched || intent.executing {
					t.Fatal("own pre-dispatch pin stranded or classified dispatched", mode, e, retired)
				}
			})
		})
	}
}

func TestWebControlConcurrentIntentClaimCannotRetireInFlightExecution(t *testing.T) {
	for _, failQualification := range []bool{true, false} {
		t.Run(fmt.Sprint(failQualification), func(t *testing.T) {
			f := newWebControlFixture(t)
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				entered, release := make(chan struct{}), make(chan struct{})
				dispatchEntered, dispatchRelease := make(chan struct{}), make(chan struct{})
				var qualifications, retirements, dispatches atomic.Int64
				f.manager.options.VerifyChannel = func(context.Context, auth.Principal, WebControlAuthority) error {
					if qualifications.Add(1) > 1 {
						return nil
					}
					close(entered)
					<-release
					if failQualification {
						return errors.New("pinned verification refused")
					}
					return nil
				}
				f.manager.options.ExecutePinned = func(context.Context, auth.Principal, model.Step, map[string]model.Value, WebControlAuthority) (automation.StepResult, error) {
					dispatches.Add(1)
					close(dispatchEntered)
					<-dispatchRelease
					return automation.StepResult{DispatchState: "dispatched"}, nil
				}
				f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
					retirements.Add(1)
					return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
				}
				done := make(chan error, 1)
				go func() { _, e := f.manager.Execute(prepared, p, step, nil); done <- e }()
				<-entered
				if r, e := f.manager.Execute(prepared, p, step, nil); !errors.Is(e, ErrWebControlIntent) || r.DispatchState != "notDispatched" || retirements.Load() != 0 || qualifications.Load() != 1 {
					t.Error("concurrent caller borrowed pin", e)
				}
				close(release)
				if !failQualification {
					<-dispatchEntered
					if _, e := f.manager.Execute(prepared, p, step, nil); !errors.Is(e, ErrWebControlIntent) || retirements.Load() != 0 {
						t.Error("duplicate retired in-flight input", e)
					}
					close(dispatchRelease)
				}
				e := <-done
				if failQualification != (e != nil) || retirements.Load() != 1 || dispatches.Load() != map[bool]int64{true: 0, false: 1}[failQualification] {
					t.Error("single owner lifecycle failed", e)
				}
			})
		})
	}
}

func TestWebControlAcquisitionValidationRetiresOnlyNewlyOwnedPins(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		for _, mode := range []string{"readiness", "action", "postcondition", "invalidPostcondition"} {
			t.Run(fmt.Sprint(fresh)+mode, func(t *testing.T) {
				f := newWebControlFixture(t)
				f.ready.NewlyAcquired = fresh
				if mode == "readiness" {
					f.ready.KernelPeerQualified = false
				}
				if mode == "action" {
					f.ready.Actions = nil
				}

				retired := 0
				f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
					retired++
					return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
				}
				withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
					if mode == "postcondition" || mode == "invalidPostcondition" {
						step.Postcondition = &model.Predicate{Kind: "adapter", Adapter: "web", Name: "valueEquals", Scope: model.PredicateScope{Target: &step.Target}, Inputs: map[string]model.Value{}, TimeoutMs: 1000, FreshnessMs: 1000, RequiredAuthority: "observational"}
						if mode == "postcondition" {
							for key, value := range map[string]string{"origin": "https://fixture.test", "strategy": "id", "selector": "save", "attribute": "text", "expected": "saved"} {
								step.Postcondition.Inputs[key] = model.Value{Kind: model.StringValue, String: value}
							}
							if e := step.Postcondition.Validate(); e != nil {
								t.Fatal(e)
							}
						}
					}
					if _, _, e := f.manager.Prepare(ctx, p, step); e == nil {
						t.Error("invalid preparation admitted")
					}
				})
				expected := 0
				if fresh && mode != "invalidPostcondition" {
					expected = 1
				}
				if mode == "invalidPostcondition" && f.qualifications != 0 {
					t.Fatal("invalid static predicate acquired a renderer")
				}
				if retired != expected || f.dispatches != 0 {
					t.Fatal("acquisition provenance ignored", retired, expected)
				}
			})
		}
	}
}

func TestWebControlCapabilitiesRetireFreshProbeButNeverBorrowedPin(t *testing.T) {
	for _, fresh := range []bool{true, false} {
		t.Run(fmt.Sprint(fresh), func(t *testing.T) {
			f := newWebControlFixture(t)
			f.ready.NewlyAcquired = fresh
			retired := 0
			f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
				retired++
				return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
			}
			if !f.manager.Capabilities(f.ctx, f.principal)["web:semanticPress"] {
				t.Fatal("metadata capability missing")
			}
			expected := 0
			if fresh {
				expected = 1
			}
			if retired != expected || f.dispatches != 0 {
				t.Fatal("probe leaked or retired borrowed pin")
			}
		})
	}
}

func TestWebControlCloseOwnsPreparedPinsAndRetainsUncertainCleanup(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			f := newWebControlFixture(t)
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				intent := prepared.Value(webControlIntentKey{}).(*webControlIntent)
				retired, closed := 0, 0
				f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
					retired++
					return WebControlCleanup{AuthorityRetired: !uncertain, RetiredAuthorityQuiesced: !uncertain, UnknownExecutors: uncertain}, nil
				}
				f.manager.options.Close = func(context.Context) error { closed++; return nil }
				bounded, cancel := context.WithTimeout(ctx, time.Second)
				defer cancel()
				e := f.manager.Close(bounded)
				if (e != nil) != uncertain || retired != 1 || f.dispatches != 0 || closed != map[bool]int{true: 0, false: 1}[uncertain] {
					t.Fatal("Close lost owned pin/proof", e)
				}
				if !uncertain && (!intent.consumed || intent.dispatched) {
					t.Fatal("prepared Close claimed input")
				}
			})
		})
	}
}

func TestWebControlCloseDrainsDispatchBeforeClosingProvider(t *testing.T) {
	f := newWebControlFixture(t)
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		entered, release := make(chan struct{}), make(chan struct{})
		var retired, closed atomic.Int64
		f.manager.options.ExecutePinned = func(context.Context, auth.Principal, model.Step, map[string]model.Value, WebControlAuthority) (automation.StepResult, error) {
			close(entered)
			<-release
			return automation.StepResult{DispatchState: "dispatched"}, nil
		}
		f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
			retired.Add(1)
			return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
		}
		f.manager.options.Close = func(context.Context) error { closed.Add(1); return nil }
		done := make(chan error, 1)
		go func() { _, e := f.manager.Execute(prepared, p, step, nil); done <- e }()
		<-entered
		limit, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		e := f.manager.Close(limit)
		cancel()
		if !errors.Is(e, context.DeadlineExceeded) || closed.Load() != 0 || retired.Load() != 0 {
			t.Fatal("Close tore down active dispatch", e)
		}
		close(release)
		if e = <-done; e != nil {
			t.Fatal(e)
		}
		if e = f.manager.Close(ctx); e != nil || closed.Load() != 1 || retired.Load() != 1 {
			t.Fatal("drained close failed", e)
		}
	})
}

func TestWebControlCloseRacingAdmissionRetiresUnpublishedManagerPin(t *testing.T) {
	f := newWebControlFixture(t)
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		entered, release := make(chan struct{}), make(chan struct{})
		var retired, closed atomic.Int64
		original := f.manager.options.Qualify
		f.manager.options.Qualify = func(c context.Context, p auth.Principal, s model.Surface) (WebControlReadiness, error) {
			r, e := original(c, p, s)
			close(entered)
			<-release
			return r, e
		}
		f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
			retired.Add(1)
			return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
		}
		f.manager.options.Close = func(context.Context) error { closed.Add(1); return nil }
		done := make(chan error, 1)
		go func() { _, _, e := f.manager.Prepare(ctx, p, step); done <- e }()
		<-entered
		limit, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
		e := f.manager.Close(limit)
		cancel()
		if !errors.Is(e, context.DeadlineExceeded) || closed.Load() != 0 || retired.Load() != 0 {
			t.Fatal("Close ignored admission work", e)
		}
		close(release)
		if e = <-done; e == nil {
			t.Fatal("closed manager published a pin")
		}
		if e = f.manager.Close(ctx); e != nil || closed.Load() != 1 || retired.Load() != 1 {
			t.Fatal("admission pin stranded after Close", e)
		}
	})
}

func TestWebControlCancelledPreparationRetiresWithoutExecute(t *testing.T) {
	f := newWebControlFixture(t)
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		child, cancel := context.WithCancel(ctx)
		var retired atomic.Int64
		finished := make(chan struct{})
		f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
			retired.Add(1)
			close(finished)
			return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
		}
		if _, _, e := f.manager.Prepare(child, p, step); e != nil {
			t.Fatal(e)
		}
		cancel()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Fatal("cancelled preparation remained pinned")
		}
		if retired.Load() != 1 || f.dispatches != 0 {
			t.Fatal("cancelled preparation dispatched")
		}
	})
}

func TestWebControlConfirmedDispatchSurvivesLateCancellationWithoutEffectVerification(t *testing.T) {
	f := newWebControlFixture(t)
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		var cancel context.CancelFunc
		f.manager.options.Authorize = func(c context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
			child, stop := context.WithCancel(c)
			cancel = stop
			return &consent.Lease{Context: child, Release: func() {}}, nil
		}
		f.manager.options.ExecutePinned = func(context.Context, auth.Principal, model.Step, map[string]model.Value, WebControlAuthority) (automation.StepResult, error) {
			cancel()
			return automation.StepResult{DispatchState: "dispatched", VerificationState: "verified"}, nil
		}
		result, e := f.manager.Execute(prepared, p, step, nil)
		if e != nil || result.DispatchState != "dispatched" || result.VerificationState != "unknown" || result.Postcondition != nil {
			t.Fatal("known dispatch receipt lost or business effect inferred", result, e)
		}
	})
}

func TestWebControlDestinationLeaseMustKeepOriginalGrantAndReleaseOnError(t *testing.T) {
	for _, mode := range []string{"foreignGrant", "errorWithLease"} {
		t.Run(mode, func(t *testing.T) {
			f := newWebControlFixture(t)
			f.step.Action = "browser.navigate"
			f.step.Target.Locator = nil
			f.step.Arguments = map[string]model.Value{"url": {Kind: model.StringValue, String: "https://other.test/path"}}
			f.ready.Actions = append(f.ready.Actions, "browser.navigate")
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				released := 0
				retired := 0
				f.manager.options.Authorize = func(c context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
					var e error
					if s.Origin != step.Target.Surface.Origin {
						if mode == "foreignGrant" {
							binding, _ := auth.ConsentBindingFromContext(c)
							binding.GrantID = "foreign"
							c = auth.WithConsentBinding(c, binding)
						} else {
							e = auth.ErrUnauthorized
						}
					}
					return &consent.Lease{Context: c, Release: func() { released++ }}, e
				}
				f.manager.options.Retire = func(context.Context, auth.Principal, WebControlAuthority) (WebControlCleanup, error) {
					retired++
					return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
				}
				r, e := f.manager.Execute(prepared, p, step, nil)
				if e == nil || r.DispatchState != "notDispatched" || f.dispatches != 0 || released != 2 || retired != 1 {
					t.Fatal("destination consent was borrowed/leaked", released, retired, e)
				}
			})
		})
	}
}

func TestWebRetirementRecoveryPreservesReceiptAndReleasesLeaseOnce(t *testing.T) {
	for _, state := range []string{"dispatched", "notDispatched", "unknown"} {
		t.Run(state, func(t *testing.T) {
			f := newWebControlFixture(t)
			consumed := 0
			f.manager.options.RetireConsumed = func(actor auth.Principal, a WebControlAuthority) {
				if actor.ClientID != f.principal.ClientID || a != f.ready.Authority {
					t.Error("foreign completion consumed")
				}
				consumed++
			}
			f.cleanup = WebControlCleanup{UnknownExecutors: true}
			f.dispatchedResult = automation.StepResult{DispatchState: state}
			if state == "notDispatched" {
				f.dispatchErr = &model.MechanizeError{Code: "fixtureAbsent", DispatchState: state}
			}
			withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
				prepared := prepareWeb(t, f, ctx, p, step)
				result, err := f.manager.Execute(prepared, p, step, nil)
				if !errors.Is(err, ErrWebControlCleanupUnknown) || result.DispatchState != state || f.releases != 0 {
					t.Fatal("original receipt/hold lost", result, err)
				}
				intent := prepared.Value(webControlIntentKey{}).(*webControlIntent)
				foreign := p
				foreign.ClientID = "foreign"
				if err := f.manager.reconcileRetirements(auth.WithPrincipal(context.Background(), foreign), foreign); err != nil || intent.lease == nil {
					t.Fatal("foreign recovery consumed owned lease")
				}
				f.cleanup = WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}
				entered, resume := make(chan struct{}), make(chan struct{})
				f.manager.options.Retire = func(c context.Context, actor auth.Principal, a WebControlAuthority) (WebControlCleanup, error) {
					if a != intent.authority || actor.ClientID != p.ClientID {
						t.Error("retry replaced original actor/authority")
					}
					close(entered)
					<-resume
					return f.cleanup, nil
				}
				done := make(chan error, 1)
				fresh := auth.WithPrincipal(context.Background(), p)
				go func() { done <- f.manager.reconcileRetirements(fresh, p) }()
				<-entered
				if err := f.manager.reconcileRetirements(fresh, p); !errors.Is(err, ErrWebControlCleanupUnknown) {
					t.Fatal("concurrent retry admitted", err)
				}
				close(resume)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if err := f.manager.reconcileRetirements(fresh, p); err != nil {
					t.Fatal(err)
				}
				if f.releases != 1 || consumed != 1 || f.dispatches != 1 || result.DispatchState != state || intent.lease != nil || !intent.consumed {
					t.Fatal("recovery replayed input or duplicated lease release")
				}
				if _, err := f.manager.Execute(prepared, p, step, nil); !errors.Is(err, ErrWebControlIntent) {
					t.Fatal("retired intent replayed", err)
				}
			})
		})
	}
}

func TestWebCloseReleasesRecoveredLeaseOnce(t *testing.T) {
	f := newWebControlFixture(t)
	f.cleanup = WebControlCleanup{UnknownExecutors: true}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		if _, err := f.manager.Execute(prepared, p, step, nil); !errors.Is(err, ErrWebControlCleanupUnknown) {
			t.Fatal(err)
		}
		f.cleanup = WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}
		if err := f.manager.Close(auth.WithPrincipal(context.Background(), p)); err != nil {
			t.Fatal(err)
		}
		if err := f.manager.Close(auth.WithPrincipal(context.Background(), p)); err != nil {
			t.Fatal(err)
		}
		if f.releases != 1 || f.dispatches != 1 {
			t.Fatal("Close replayed or duplicated release")
		}
	})
}

func TestWebRetirementRecoveryHasOneOverallDeadline(t *testing.T) {
	f := newWebControlFixture(t)
	for i := 0; i < 3; i++ {
		a := f.ready.Authority
		a.ID = fmt.Sprint(i)
		f.manager.prepared[&webControlIntent{principal: f.principal, authority: a, cleanupPending: true}] = struct{}{}
	}
	f.manager.options.Retire = func(ctx context.Context, _ auth.Principal, _ WebControlAuthority) (WebControlCleanup, error) {
		<-ctx.Done()
		return WebControlCleanup{UnknownExecutors: true}, ctx.Err()
	}
	started := time.Now()
	err := f.manager.reconcileRetirements(auth.WithPrincipal(context.Background(), f.principal), f.principal)
	if !errors.Is(err, ErrWebControlCleanupUnknown) || time.Since(started) > 3*time.Second {
		t.Fatal("recovery multiplied retained-intent deadlines", err)
	}
	for intent := range f.manager.prepared {
		if intent.executing || !intent.cleanupPending {
			t.Fatal("timeout lost lifecycle hold")
		}
	}
}

func TestWebRetainedTargetDoesNotBlockAnotherTargetAndCloseOwnsBoth(t *testing.T) {
	f := newWebControlFixture(t)
	f.dispatchedResult = automation.StepResult{DispatchState: "unknown"}
	f.cleanup = WebControlCleanup{UnknownExecutors: true}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		first := prepareWeb(t, f, ctx, p, step)
		original, err := f.manager.Execute(first, p, step, nil)
		if !errors.Is(err, ErrWebControlCleanupUnknown) || original.DispatchState != "unknown" {
			t.Fatal(original, err)
		}
		a := first.Value(webControlIntentKey{}).(*webControlIntent)
		f.ready.Authority.ID = "second-authority"
		f.ready.Authority.Document.TabID = 12
		f.ready.Authority.Document.DocumentID = "second-document"
		secondStep := step
		secondStep.Target.Surface.TabID = f.ready.Authority.Document.QualifiedTabID()
		second := prepareWeb(t, f, ctx, p, secondStep)
		f.dispatchedResult = automation.StepResult{DispatchState: "dispatched"}
		// Both exact leases lose cleanup ACKs, independently retaining their intents.
		if result, err := f.manager.Execute(second, p, secondStep, nil); !errors.Is(err, ErrWebControlCleanupUnknown) || result.DispatchState != "dispatched" {
			t.Fatal(result, err)
		}
		b := second.Value(webControlIntentKey{}).(*webControlIntent)
		if f.dispatches != 2 || f.releases != 0 || a.lease == nil || b.lease == nil {
			t.Fatal("B blocked or A released without proof")
		}
		var retired []WebControlAuthority
		f.manager.options.Retire = func(_ context.Context, _ auth.Principal, authority WebControlAuthority) (WebControlCleanup, error) {
			retired = append(retired, authority)
			return WebControlCleanup{AuthorityRetired: true, RetiredAuthorityQuiesced: true}, nil
		}
		if err := f.manager.Close(auth.WithPrincipal(context.Background(), p)); err != nil {
			t.Fatal(err)
		}
		if len(retired) != 2 || f.releases != 2 || !a.consumed || !b.consumed || original.DispatchState != "unknown" {
			t.Fatal("Close did not own both targets independently")
		}
	})
}
