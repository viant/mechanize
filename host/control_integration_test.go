package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/datly/exec"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	datahost "github.com/viant/mechanize/data/host"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/session"
)

func hostControlFixture(t *testing.T) (*Host, *controlFixture) {
	t.Helper()
	f := newControlFixture(t)
	h := &Host{nativeControl: f.manager, users: map[string]User{f.principal.Namespace: {NativeBundles: append([]string(nil), f.enrolled...)}}}
	return h, f
}
func controlStep() model.Step {
	return model.Step{ID: "save", Action: "element.press", TimeoutMs: 1000, Effect: model.Effect{Class: model.ExternalNonIdempotent}, Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.fixture.app"}, Cardinality: "one", Locator: &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "save"}, Exact: true}}}
}
func TestHostNativeControlAbsentFailsClosed(t *testing.T) {
	h, f := hostControlFixture(t)
	h.nativeControl = nil
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || policy.AllowMutation {
		t.Fatalf("default authority: %+v %v", policy, err)
	}
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); !errors.Is(err, ErrNativeControlUnqualified) {
		t.Fatalf("epoch: %v", err)
	}
	result, err := h.execute(f.ctx, f.principal, controlStep(), nil)
	if err == nil || result.DispatchState != "notDispatched" || f.starts != 0 {
		t.Fatalf("default dispatch: %+v %v starts=%d", result, err, f.starts)
	}
}
func TestHostNativeControlPolicyAndPreIntentEpoch(t *testing.T) {
	h, f := hostControlFixture(t)
	policy, err := h.Policy(f.ctx, f.principal)
	if err != nil || !policy.AllowMutation {
		t.Fatalf("qualified policy: %+v %v", policy, err)
	}
	if err := (script.Validator{}).CheckPolicy(&model.Plan{SchemaVersion: 1, Steps: []model.Step{controlStep()}}, policy); err != nil {
		t.Fatal(err)
	}
	epoch, err := h.controlLeaseEpoch(f.ctx, f.principal)
	if err != nil || epoch != 1 || f.calls != 0 {
		t.Fatalf("pre-intent: %d %v calls=%d", epoch, err, f.calls)
	}
	// No dispatch can occur without exact human consent, even with a held fence.
	ctx, _ := data.WithScope(f.ctx, data.Scope{Namespace: f.principal.Namespace, LeaseEpoch: epoch})
	result, err := h.execute(ctx, f.principal, controlStep(), nil)
	if err == nil || result.DispatchState != "notDispatched" || f.calls != 0 {
		t.Fatalf("missing consent: %+v %v calls=%d", result, err, f.calls)
	}
	stale, _ := data.WithScope(f.ctx, data.Scope{Namespace: f.principal.Namespace, LeaseEpoch: epoch + 1})
	_, err = h.execute(stale, f.principal, controlStep(), nil)
	if !errors.Is(err, session.ErrNoLease) || f.calls != 0 {
		t.Fatalf("stale epoch: %v", err)
	}
}
func TestHostNativeControlDoesNotEnableBrowser(t *testing.T) {
	h, f := hostControlFixture(t)
	caps := map[string]bool{"web:element.press": true, "web:element.fill": true, "web:browser.navigate": true, "web:browser.activate": true, "web:element.read": true}
	if !h.nativeControlPolicy(f.ctx, f.principal, caps) {
		t.Fatal("fixture unqualified")
	}
	for _, key := range []string{"web:element.press", "web:element.fill", "web:browser.navigate", "web:browser.activate"} {
		if caps[key] {
			t.Fatalf("native grant enabled %s", key)
		}
	}
	if !caps["web:element.read"] {
		t.Fatal("observation removed")
	}
	step := controlStep()
	step.Target.Surface = model.Surface{Kind: "web", Origin: "https://fixture.test"}
	result, err := h.execute(f.ctx, f.principal, step, nil)
	if !errors.Is(err, ErrWebControlUnqualified) || result.DispatchState != "notDispatched" || f.calls != 0 {
		t.Fatalf("browser dispatch: %+v %v", result, err)
	}
}
func TestHostNativeControlUsesVerifiedEnrollment(t *testing.T) {
	h, f := hostControlFixture(t)
	h.users[f.principal.Namespace] = User{NativeBundles: []string{"com.foreign.app"}}
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); !errors.Is(err, auth.ErrUnauthorized) || f.starts != 0 {
		t.Fatalf("foreign ceiling: %v starts=%d", err, f.starts)
	}
	h.users[f.principal.Namespace] = User{NativeBundles: f.enrolled}
	policy, err := h.Policy(context.Background(), f.principal)
	if !errors.Is(err, auth.ErrUnauthorized) || policy.AllowMutation {
		t.Fatalf("missing actor: %+v %v", policy, err)
	}
}
func TestHostCloseOwnsNativeControl(t *testing.T) {
	h, f := hostControlFixture(t)
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.alive || !f.manager.closed {
		t.Fatal("host did not stop manager")
	}
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); err == nil {
		t.Fatal("closed host readmitted input")
	}
}

type hostDispatchHelper struct {
	*controlFixture
	mutations      int
	dispatchErr    error
	dispatchCancel context.CancelFunc
}

func (f *hostDispatchHelper) Call(ctx context.Context, request native.Request) (native.Reply, error) {
	result := any(map[string]any{})
	reply := native.Reply{HelperEpoch: "fixture"}
	switch request.Method {
	case "doctor":
		result = map[string]any{"axTrusted": !f.manager.options.LaunchOnly, "mutationEnabled": !f.manager.options.LaunchOnly, "launchEnabled": true}
	case "apps.list":
		result = map[string]any{"complete": true, "apps": []map[string]any{{"pid": 1, "bundleID": "com.fixture.app", "launchTime": "fixture-launch", "startToken": "fixture-start"}}}
	case "elements.snapshot":
		result = map[string]any{"observationId": "obs", "generation": 1, "complete": true, "nodes": []map[string]any{{"ref": "button", "nativeRole": "AXButton", "identifier": "save", "enabled": true}}, "startedAt": "2026-10-01T00:00:00Z", "returnedAt": "2026-10-01T00:00:00Z"}
	case "app.launch":
		f.mutations++
		reply.Receipt = &native.Receipt{DispatchState: "dispatched"}
		reply.Result, _ = json.Marshal(map[string]any{"bundleID": "com.fixture.app", "pid": 1, "launchTime": "fixture-launch", "startToken": "fixture-start", "active": false})
		return reply, nil
	case "elements.press":
		f.mutations++
		if f.dispatchCancel != nil {
			f.dispatchCancel()
		}
		if f.dispatchErr == nil {
			reply.Receipt = &native.Receipt{DispatchState: "dispatched"}
		}
		reply.Result, _ = json.Marshal(result)
		return reply, f.dispatchErr
	}
	reply.Result, _ = json.Marshal(result)
	return reply, nil
}
func TestHostNativeDispatchConsentCleanup(t *testing.T) {
	for _, mode := range []string{"clean", "launch-only", "disconnect", "cancel", "slow-persistence", "persistence-outage"} {
		unknown := mode != "clean" && mode != "launch-only"
		t.Run(fmt.Sprintf("cleanup=%s", mode), func(t *testing.T) {
			h, f := hostControlFixture(t)

			f.principal.Scopes = append(f.principal.Scopes, "consent:admin")
			f.principal.ClientID = "fixture-agent"
			f.principal.ClientName = "Fixture Agent"
			f.ctx = auth.WithPrincipal(context.Background(), f.principal)
			helper := &hostDispatchHelper{controlFixture: f}
			f.unknown = unknown
			if unknown {
				helper.dispatchErr = &native.TransportError{DispatchState: "unknown", Cause: errors.New("lost helper receipt")}
			}
			f.manager.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) { return helper, nil }
			_, file, _, _ := runtime.Caller(0)
			source := filepath.Dir(filepath.Dir(file))
			scope := data.Scope{Namespace: f.principal.Namespace}
			scoped, err := data.WithScope(f.ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			server, err := datahost.Open(scoped, source, t.TempDir(), scope)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Shutdown(context.Background())
			cleanupWrites := 0
			h.consent, err = NewConsentBroker(ConsentBrokerOptions{
				Invoke: func(ctx context.Context, p auth.Principal, request exec.ComponentRequest) (any, error) {
					if strings.HasSuffix(request.Target.Route.Path, "/consentrevoke") {
						cleanupWrites++
						if mode == "persistence-outage" {
							// The injected database reports an unconfirmed timed-out write.
							return nil, context.DeadlineExceeded
						}
						if mode == "slow-persistence" && cleanupWrites == 1 {
							timer := time.NewTimer(3500 * time.Millisecond)
							defer timer.Stop()
							select {
							case <-timer.C:
							case <-ctx.Done():
								return nil, ctx.Err()
							}
						}
					}
					return server.InvokeComponent(ctx, request)
				},
				Enrolled: h.enrolled, SessionOwned: func(ctx context.Context, p auth.Principal, id string) error {
					if id != "fixture-session" {
						return auth.ErrUnauthorized
					}
					return nil
				}, Policy: h.ConsentPolicy,
			})
			if err != nil {
				t.Fatal(err)
			}
			in := consent.RequestInput{Scope: consent.Scope{Kind: "application", BundleID: "com.fixture.app"}, Modes: []consent.Mode{consent.Control}, Purpose: "Save fixture", DurationSeconds: 60}
			request, err := h.consent.Request(f.ctx, f.principal, "fixture-session", in)
			if err != nil {
				t.Fatal(err)
			}
			human, err := auth.WithNativeHuman(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowSession})
			value, err := h.consent.NativeRPC(human, "decide", decision)
			if err != nil {
				t.Fatal(err)
			}
			grant := value.(*consent.Grant)
			bound := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: "fixture-session", GrantID: grant.ID, Purpose: in.Purpose})
			epoch, err := h.controlLeaseEpoch(bound, f.principal)
			if err != nil {
				t.Fatal(err)
			}
			bound, err = data.WithScope(bound, data.Scope{Namespace: f.principal.Namespace, LeaseEpoch: epoch})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				var cancel context.CancelFunc
				bound, cancel = context.WithCancel(bound)
				helper.dispatchCancel = cancel
				defer cancel()
			}
			step := controlStep()
			if mode == "launch-only" {
				step.Action = "app.open"
				step.Target.Locator = nil
			}
			result, err := h.execute(bound, f.principal, step, nil)
			if helper.mutations != 1 {
				t.Fatalf("dispatch count %d", helper.mutations)
			}
			if unknown {
				if !errors.Is(err, ErrNativeControlCleanupUnknown) || result.DispatchState != "unknown" {
					t.Fatalf("unknown cleanup: %+v %v", result, err)
				}
				if mode == "persistence-outage" {
					var actionable *model.MechanizeError
					if !errors.Is(err, ErrNativeControlCleanupPersistence) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &actionable) || actionable.Code != "cleanupPersistenceUnknown" || actionable.RetryableRead {
						t.Fatalf("missing actionable persistence failure: %v", err)
					}
					if _, e := h.controlLeaseEpoch(bound, f.principal); e == nil {
						t.Fatal("metadata failure readmitted physical input")
					}
					boundServiceCtx, service, e := h.consent.bound(bound, f.principal)
					if e != nil {
						t.Fatal(e)
					}
					if _, e = service.Authorize(boundServiceCtx, consent.Operation{GrantID: grant.ID, SessionID: "fixture-session", Scope: in.Scope, Mode: consent.Control, Purpose: in.Purpose}); e == nil {
						t.Fatal("metadata failure enabled another consent lease")
					}
					return
				}
				if errors.Is(err, ErrNativeControlCleanupPersistence) {
					t.Fatalf("unexpected persistence failure: %v", err)
				}
				snapshot, e := h.consent.GetSnapshot(human, f.principal)
				if e != nil {
					t.Fatal(e)
				}
				if len(snapshot.Grants) != 1 || snapshot.Grants[0].RevocationState != consent.CleanupUnknown {
					t.Fatalf("unknown not persisted: %+v", snapshot)
				}
				if _, e := h.controlLeaseEpoch(bound, f.principal); e == nil {
					t.Fatal("uncertain cleanup readmitted")
				}
			} else {
				if mode == "launch-only" && result.VerificationState != "verified" {
					t.Fatalf("independent app-running effect not verified: %+v", result)
				}
				if err != nil || result.DispatchState != "dispatched" || f.alive {
					t.Fatalf("cleanup: %+v %v alive=%v", result, err, f.alive)
				}
				revoke, _ := json.Marshal(map[string]any{"grantID": grant.ID})
				var state any
				for i := 0; i < 3; i++ {
					state, err = h.consent.NativeRPC(human, "revoke", revoke)
					if err != nil {
						t.Fatal(err)
					}
				}
				if state.(map[string]any)["status"] != consent.Revoked {
					t.Fatalf("admitted lease not released: %+v", state)
				}
			}
		})
	}
}

func TestHostControlOptionsCannotReplaceEnrollmentOrOwner(t *testing.T) {
	h, f := hostControlFixture(t)
	h.nativeControl = nil
	untrustedOwner, cancel := context.WithCancel(context.Background())
	cancel()
	options := f.options
	options.Owner = untrustedOwner
	options.Enrolled = func(context.Context, auth.Principal) ([]string, error) { return []string{"com.foreign.app"}, nil }
	if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.identity.Executable}, HostOptions{NativeControl: &options}); err != nil {
		t.Fatal(err)
	}
	defer h.Close(context.Background())
	if _, err := h.controlLeaseEpoch(f.ctx, f.principal); err != nil {
		t.Fatalf("host owner/enrollment not bound: %v", err)
	}
	options.HelperPath = "/different/helper"
	if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.identity.Executable}, HostOptions{NativeControl: &options}); err == nil {
		t.Fatal("different helper accepted")
	}
}
