package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

type controlFixture struct {
	callErr                                                         error
	mu                                                              sync.Mutex
	identity                                                        session.ProcessIdentity
	alive                                                           bool
	identityErr, stopErr                                            error
	unknown                                                         bool
	calls, starts, qualifications, executableChecks, identityChecks int
	ready                                                           NativeControlReadiness
	enrolled                                                        []string
	owner                                                           context.Context
	cancel                                                          context.CancelFunc
	options                                                         NativeControlOptions
	manager                                                         *NativeControlManager
	principal                                                       auth.Principal
	ctx                                                             context.Context
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	f := &controlFixture{alive: true, enrolled: []string{"com.fixture.app"}}
	f.principal, _ = auth.NewPrincipal("issuer", "tenant", "subject", []string{"desktop:control"})
	f.ctx = auth.WithPrincipal(context.Background(), f.principal)
	f.owner, f.cancel = context.WithCancel(context.Background())
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f.identity = session.ProcessIdentity{PID: 777, StartToken: "fixture-start", Executable: filepath.Join(dir, "helper"), UID: uint32(os.Getuid())}
	f.ready = NativeControlReadiness{IdentityQualified: true, ActiveGraphicalSession: true, Unlocked: true, Accessibility: true, EventPost: true, WatchdogLive: true, MutationQualified: true, QualifiedBundles: []string{"com.fixture.app"}}
	f.options = NativeControlOptions{
		LockPath: filepath.Join(dir, "desktop.lock"), HelperPath: f.identity.Executable, Owner: f.owner,
		Enrolled: func(context.Context, auth.Principal) ([]string, error) {
			return append([]string(nil), f.enrolled...), nil
		},
		VerifyExecutable: func(context.Context, string) error { f.executableChecks++; return nil },
		VerifyIdentity:   func(context.Context, session.ProcessIdentity) error { f.identityChecks++; return f.identityErr },
		Qualify: func(context.Context, auth.Principal, session.ProcessIdentity, []string) (NativeControlReadiness, error) {
			f.qualifications++
			r := f.ready
			if r.ValidUntil.IsZero() {
				r.ValidUntil = time.Now().Add(time.Second)
			}
			return r, nil
		},
		Inspect: func(int) (session.ProcessIdentity, bool, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.identity, f.alive, nil
		},
		HelperFactory: func(context.Context, native.Options) (NativeControlHelper, error) { f.starts++; return f, nil },
	}
	var err error
	f.manager, err = NewNativeControlManager(f.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.manager.Close(context.Background()); f.cancel() })
	return f
}
func (f *controlFixture) Identity() (session.ProcessIdentity, error) { return f.identity, nil }
func (f *controlFixture) Stop(ctx context.Context) (session.CleanupReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alive = false
	return session.CleanupReport{InputInhibited: true, HelperStopped: true, UnknownInputs: f.unknown}, errors.Join(f.stopErr, ctx.Err())
}
func (f *controlFixture) Close() error { return nil }
func (f *controlFixture) Call(context.Context, native.Request) (native.Reply, error) {
	f.calls++
	return native.Reply{HelperEpoch: "fixture"}, f.callErr
}
func (f *controlFixture) admit(t *testing.T) NativeControlAdmission {
	t.Helper()
	a, e := f.manager.Admit(f.ctx, f.principal, f.enrolled)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func (f *controlFixture) caller() *nativeControlCaller {
	return &nativeControlCaller{manager: f.manager, held: f.manager.held}
}
func mutation(f *controlFixture) native.Request {
	return native.Request{Method: "elements.press", Params: json.RawMessage(`{"expectedApp":"com.fixture.app"}`), Lease: &native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}}
}

func TestNativeControlAdmissionAndMutationGates(t *testing.T) {
	f := newControlFixture(t)
	a := f.admit(t)
	if a.Gateway == nil || a.Epoch != 1 || f.executableChecks != 1 || f.identityChecks < 2 || f.qualifications != 1 {
		t.Fatalf("admission omitted verification: %+v", a)
	}
	c := f.caller()
	r := mutation(f)
	if _, e := c.Call(f.ctx, r); e != nil {
		t.Fatal(e)
	}
	if f.calls != 1 || f.qualifications != 2 {
		t.Fatal("dispatch did not freshly qualify")
	}
	checks := []struct {
		name    string
		ctx     context.Context
		request native.Request
		change  func()
	}{
		{name: "missing identity", ctx: context.Background(), request: r},
		{name: "other owner", ctx: func() context.Context {
			p, _ := auth.NewPrincipal("issuer", "tenant", "other", []string{"desktop:control"})
			return auth.WithPrincipal(context.Background(), p)
		}(), request: r},
		{name: "observe scope", ctx: func() context.Context {
			p := f.principal
			p.Scopes = []string{"desktop:observe"}
			return auth.WithPrincipal(context.Background(), p)
		}(), request: r},
		{name: "foreign bundle", ctx: f.ctx, request: func() native.Request { v := r; v.Params = json.RawMessage(`{"expectedApp":"com.other"}`); return v }()},
		{name: "stale generation", ctx: f.ctx, request: func() native.Request { v := r; l := *v.Lease; l.Generation++; v.Lease = &l; return v }()},
		{name: "no lease", ctx: f.ctx, request: func() native.Request { v := r; v.Lease = nil; return v }()},
		{name: "raw input bypass", ctx: f.ctx, request: native.Request{Method: "input.key"}},
		{name: "removed enrollment", ctx: f.ctx, request: r, change: func() { f.enrolled = nil }},
	}
	for _, tt := range checks {
		t.Run(tt.name, func(t *testing.T) {
			if tt.change != nil {
				tt.change()
			}
			if _, e := c.Call(tt.ctx, tt.request); e == nil {
				t.Fatal("unsafe dispatch accepted")
			}
			if f.calls != 1 {
				t.Fatal("helper received denied operation")
			}
		})
	}
}

func TestNativeControlFreshReadiness(t *testing.T) {
	gates := []struct {
		name   string
		change func(*NativeControlReadiness)
	}{
		{"identity", func(r *NativeControlReadiness) { r.IdentityQualified = false }},
		{"graphical", func(r *NativeControlReadiness) { r.ActiveGraphicalSession = false }},
		{"locked", func(r *NativeControlReadiness) { r.Unlocked = false }},
		{"accessibility", func(r *NativeControlReadiness) { r.Accessibility = false }},
		{"eventPost", func(r *NativeControlReadiness) { r.EventPost = false }},
		{"watchdog", func(r *NativeControlReadiness) { r.WatchdogLive = false }},
		{"mutation", func(r *NativeControlReadiness) { r.MutationQualified = false }},
		{"expired", func(r *NativeControlReadiness) { r.ValidUntil = time.Now().Add(-time.Second) }},
		{"future", func(r *NativeControlReadiness) { r.ValidUntil = time.Now().Add(time.Minute) }},
		{"scope", func(r *NativeControlReadiness) { r.QualifiedBundles = []string{"com.other"} }},
	}
	for _, g := range gates {
		t.Run(g.name, func(t *testing.T) {
			f := newControlFixture(t)
			f.admit(t)
			g.change(&f.ready)
			if _, e := f.caller().Call(f.ctx, mutation(f)); !errors.Is(e, ErrNativeControlUnqualified) {
				t.Fatalf("qualification: %v", e)
			}
			if f.calls != 0 {
				t.Fatal("unqualified helper dispatched")
			}
		})
	}
}

func TestNativeControlMandatoryVerifiersAndAuditFailure(t *testing.T) {
	for _, missing := range []string{"executable", "identity", "qualification"} {
		t.Run(missing, func(t *testing.T) {
			f := newControlFixture(t)
			switch missing {
			case "executable":
				f.manager.options.VerifyExecutable = nil
			case "identity":
				f.manager.options.VerifyIdentity = nil
			case "qualification":
				f.manager.options.Qualify = nil
			}
			if _, e := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(e, ErrNativeControlUnqualified) {
				t.Fatal(e)
			}
			if f.starts != 0 {
				t.Fatal("unverified helper launched")
			}
		})
	}
	f := newControlFixture(t)
	f.identityErr = errors.New("audit mismatch")
	if _, e := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(e, f.identityErr) {
		t.Fatal(e)
	}
	if f.calls != 0 || f.manager.held != nil {
		t.Fatal("audit failure retained usable admission")
	}
}

func TestNativeControlSharedFenceAndExplicitTransfer(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	second, e := NewNativeControlManager(f.options)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close(context.Background())
	if _, e = second.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(e, session.ErrContended) {
		t.Fatalf("shared physical lock: %v", e)
	}
	old := f.caller()
	report, e := f.manager.Revoke(f.ctx, f.principal)
	if e != nil || !report.FenceReleased {
		t.Fatalf("clean revoke: %+v %v", report, e)
	}
	if _, e = old.Call(f.ctx, native.Request{Method: "doctor"}); !errors.Is(e, session.ErrNoLease) {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.alive = true
	f.mu.Unlock()
	a, e := second.Admit(f.ctx, f.principal, f.enrolled)
	if e != nil || a.Epoch != 2 {
		t.Fatalf("explicit generation transfer: %+v %v", a, e)
	}
}

func TestNativeControlUnknownCleanupPersistsRestartBarrier(t *testing.T) {
	for _, kind := range []string{"unknown", "error", "canceled", "unattached audit failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newControlFixture(t)
			if kind == "unattached audit failure" {
				f.identityErr = errors.New("audit failed")
				f.unknown = true
				_, _ = f.manager.Admit(f.ctx, f.principal, f.enrolled)
			} else {
				f.admit(t)
			}
			ctx := f.ctx
			switch kind {
			case "unknown":
				f.unknown = true
			case "error":
				f.stopErr = errors.New("stop failed")
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if kind != "unattached audit failure" {
				report, e := f.manager.Revoke(ctx, f.principal)
				if e == nil || report.FenceReleased || !report.UnknownInputs {
					t.Fatalf("false clean: %+v %v", report, e)
				}
			}
			data, e := os.ReadFile(f.options.LockPath)
			if e != nil {
				t.Fatal(e)
			}
			var state struct {
				LastCleanup *session.CleanupReport `json:"lastCleanup"`
			}
			if e = json.Unmarshal(data, &state); e != nil || state.LastCleanup == nil || !state.LastCleanup.UnknownInputs {
				t.Fatalf("missing durable barrier: %s %v", data, e)
			}
			// Copy the crash record to an unlocked private fence to model process death
			// without releasing the intentionally retained live fixture fence.
			dir := t.TempDir()
			_ = os.Chmod(dir, 0700)
			opts := f.options
			opts.LockPath = filepath.Join(dir, "restart.lock")
			if e = os.WriteFile(opts.LockPath, data, 0600); e != nil {
				t.Fatal(e)
			}
			restarted, e := NewNativeControlManager(opts)
			if e != nil {
				t.Fatal(e)
			}
			defer restarted.Close(context.Background())
			starts := f.starts
			if _, e = restarted.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(e, session.ErrCleanupUnknown) {
				t.Fatalf("restart cleared uncertain inputs: %v", e)
			}
			if starts != f.starts {
				t.Fatal("restart dispatched helper behind unknown barrier")
			}
		})
	}
}

func TestNativeControlCancellationAndOwnerTermination(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	caller := f.caller()
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, err := caller.Call(ctx, mutation(f)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled dispatch: %v", err)
	}
	if f.calls != 0 {
		t.Fatal("canceled request reached helper")
	}
	f.cancel()
	if _, err := caller.Call(f.ctx, native.Request{Method: "doctor"}); !errors.Is(err, session.ErrNoLease) {
		t.Fatalf("canceled owner dispatch: %v", err)
	}
	if f.calls != 0 {
		t.Fatal("terminated owner reached helper")
	}
}

func TestNativeControlFactoryErrorWithStartedHelperRetainsBarrier(t *testing.T) {
	f := newControlFixture(t)
	f.unknown = true
	startedErr := errors.New("post-launch handshake failed")
	f.manager.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) { return f, startedErr }
	if _, err := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(err, startedErr) || !errors.Is(err, ErrNativeControlCleanupUnknown) {
		t.Fatalf("post-launch error: %v", err)
	}
	data, err := os.ReadFile(f.options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		LastCleanup *session.CleanupReport `json:"lastCleanup"`
	}
	if err = json.Unmarshal(data, &state); err != nil || state.LastCleanup == nil || !state.LastCleanup.UnknownInputs {
		t.Fatalf("post-launch failure omitted barrier: %s %v", data, err)
	}
}

func TestNativeControlExecutableAndProcessIdentityRejection(t *testing.T) {
	t.Run("executable verification", func(t *testing.T) {
		f := newControlFixture(t)
		denied := errors.New("unsigned image")
		f.manager.options.VerifyExecutable = func(context.Context, string) error { return denied }
		if _, err := f.manager.Admit(f.ctx, f.principal, f.enrolled); !errors.Is(err, denied) {
			t.Fatal(err)
		}
		if f.starts != 0 {
			t.Fatal("unverified image launched")
		}
	})
	t.Run("inspected process differs", func(t *testing.T) {
		f := newControlFixture(t)
		f.manager.options.HelperFactory = func(context.Context, native.Options) (NativeControlHelper, error) {
			f.starts++
			f.identity.UID++
			return f, nil
		}
		if _, err := f.manager.Admit(f.ctx, f.principal, f.enrolled); err == nil {
			t.Fatal("wrong process UID admitted")
		}
		if f.calls != 0 {
			t.Fatal("wrong UID dispatched")
		}
	})
}

func TestNativeControlInterruptedDispatchPersistsBarrierImmediately(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	f.callErr = &native.TransportError{Cause: context.DeadlineExceeded, DispatchState: "unknown"}
	caller := f.caller()
	if _, err := caller.Call(f.ctx, mutation(f)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(f.options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	var state struct {
		LastCleanup *session.CleanupReport `json:"lastCleanup"`
	}
	if err = json.Unmarshal(data, &state); err != nil || state.LastCleanup == nil || !state.LastCleanup.UnknownInputs {
		t.Fatalf("interrupted dispatch missing crash barrier: %s %v", data, err)
	}
	if _, err = caller.Call(f.ctx, mutation(f)); !errors.Is(err, session.ErrNoLease) {
		t.Fatalf("interrupted generation still dispatchable: %v", err)
	}
	if f.calls != 1 {
		t.Fatal("interrupted generation replayed")
	}
}

func TestNativeControlPersistsExactLaunchProfileBeforeDispatch(t *testing.T) {
	for _, profile := range []session.InputProfile{session.InputProfileRaw, session.InputProfileSemantic, session.InputProfileLaunch} {
		t.Run(string(profile), func(t *testing.T) {
			f := newControlFixture(t)
			f.manager.options.SemanticOnly = profile == session.InputProfileSemantic
			f.manager.options.LaunchOnly = profile == session.InputProfileLaunch
			f.ready.SemanticQualified = true
			f.ready.LaunchQualified = true
			f.admit(t)
			raw, err := os.ReadFile(f.options.LockPath)
			if err != nil {
				t.Fatal(err)
			}
			var persisted struct {
				InputProfile session.InputProfile    `json:"inputProfile"`
				Helper       session.ProcessIdentity `json:"helper"`
			}
			if json.Unmarshal(raw, &persisted) != nil || persisted.InputProfile != profile || persisted.Helper != f.identity || f.calls != 0 {
				t.Fatalf("missing pre-dispatch historical launch profile: %+v", persisted)
			}
		})
	}
}

type ownerCancellationHelper struct {
	*controlFixture
	life    context.Context
	stopped chan bool
}

func (h *ownerCancellationHelper) Stop(ctx context.Context) (session.CleanupReport, error) {
	// Simulate exec.CommandContext: cancelled helper life means the process
	// was killed before releaseAll could return trustworthy cleanup evidence.
	premature := h.life.Err() != nil
	h.stopped <- premature
	if premature {
		return session.CleanupReport{InputInhibited: true, UnknownInputs: true}, errors.New("helper killed before cleanup")
	}
	return h.controlFixture.Stop(ctx)
}
func TestOwnerCancellationPreservesHelperUntilIndependentCleanup(t *testing.T) {
	f := newControlFixture(t)
	stopped := make(chan bool, 1)
	var helper *ownerCancellationHelper
	f.manager.options.HelperFactory = func(life context.Context, _ native.Options) (NativeControlHelper, error) {
		helper = &ownerCancellationHelper{controlFixture: f, life: life, stopped: stopped}
		return helper, nil
	}
	f.admit(t)
	f.cancel() // Parent cancellation precedes cleanup, as during broker shutdown.
	select {
	case premature := <-stopped:
		if premature {
			t.Fatal("owner cancellation killed helper before cleanup")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("owner cancellation did not initiate bounded helper cleanup")
	}
	report, err := f.manager.Close(context.Background())
	if err != nil || report.UnknownInputs || !report.FenceReleased {
		t.Fatalf("clean owner shutdown retained unknown fence: %+v %v", report, err)
	}
	if helper.life.Err() == nil {
		t.Fatal("helper lifetime not cancelled after confirmed cleanup")
	}
	raw, err := os.ReadFile(f.options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		LastCleanup session.CleanupReport `json:"lastCleanup"`
	}
	if json.Unmarshal(raw, &saved) != nil || saved.LastCleanup.UnknownInputs {
		t.Fatal("owner shutdown persisted false input uncertainty")
	}
}

func TestNativeControlWindowRoutesRequireExactScopeAndMutationLease(t *testing.T) {
	for _, method := range []string{"windows.list", "windows.setPosition"} {
		for _, mode := range []string{"allowed", "semantic", "missingScope", "wrongScopeKey", "foreignScope", "malformedScope", "missingActor", "foreignActor", "observeActor", "missingLease", "wrongLeaseID", "wrongLeaseGeneration", "launchOnly"} {
			t.Run(method+"_"+mode, func(t *testing.T) {
				f := newControlFixture(t)
				if mode == "semantic" {
					f.manager.options.SemanticOnly = true
					f.ready.SemanticQualified = true
					f.ready.EventPost = false
					f.ready.MutationQualified = false
				}
				if mode == "launchOnly" {
					f.manager.options.LaunchOnly = true
					f.ready.LaunchQualified = true
				}
				f.admit(t)
				caller := f.caller()
				lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
				scopeKey := "expectedApp"
				if method == "windows.list" {
					scopeKey = "bundleID"
				}
				params := map[string]any{scopeKey: "com.fixture.app", "generation": 1, "elementRef": "window", "position": map[string]int{"x": 100, "y": 100}}
				ctx := f.ctx
				switch mode {
				case "missingScope":
					delete(params, scopeKey)
				case "wrongScopeKey":
					delete(params, scopeKey)
					wrong := "bundleID"
					if method == "windows.list" {
						wrong = "expectedApp"
					}
					params[wrong] = "com.fixture.app"
				case "foreignScope":
					params[scopeKey] = "com.foreign.app"
				case "missingActor":
					ctx = context.Background()
				case "foreignActor":
					p, _ := auth.NewPrincipal("issuer", "tenant", "foreign", []string{"desktop:control"})
					ctx = auth.WithPrincipal(context.Background(), p)
				case "observeActor":
					p := f.principal
					p.Scopes = []string{"desktop:observe"}
					ctx = auth.WithPrincipal(context.Background(), p)
				case "wrongLeaseID":
					lease.ID = "foreign"
				case "wrongLeaseGeneration":
					lease.Generation++
				}
				body, _ := json.Marshal(params)
				if mode == "malformedScope" {
					body = json.RawMessage(`{"bundleID":42,"expectedApp":42}`)
				}
				request := native.Request{Method: method, Params: body}
				if method == "windows.setPosition" {
					request.Lease = &lease
				}
				if mode == "missingLease" {
					request.Lease = nil
				}
				_, err := caller.Call(ctx, request)
				allowed := mode == "allowed" || mode == "semantic" || method == "windows.list" && (mode == "missingLease" || mode == "wrongLeaseID" || mode == "wrongLeaseGeneration")
				if allowed {
					if err != nil || f.calls != 1 {
						t.Fatalf("qualified window route rejected: %v calls%d", err, f.calls)
					}
				} else if err == nil || f.calls != 0 {
					t.Fatalf("unqualified window route reached helper: %v calls%d", err, f.calls)
				}
			})
		}
	}
}

func TestNativeControlSelectedTextAndPrivateComparisonScope(t *testing.T) {
	for _, method := range []string{"elements.replaceText", "elements.valueMatches"} {
		for _, mode := range []string{"allowed", "foreign", "missingScope", "noLease", "wrongLease", "launchOnly"} {
			t.Run(method+mode, func(t *testing.T) {
				f := newControlFixture(t)
				if mode == "launchOnly" {
					f.manager.options.LaunchOnly = true
					f.ready.LaunchQualified = true
				}
				f.admit(t)
				request := native.Request{Method: method, Params: json.RawMessage(`{"expectedApp":"com.fixture.app","elementRef":"field","generation":1,"value":"literal","expected":"literal"}`)}
				if method == "elements.replaceText" {
					request.Lease = &native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
				}
				switch mode {
				case "foreign":
					request.Params = json.RawMessage(`{"expectedApp":"com.foreign.app"}`)
				case "missingScope":
					request.Params = json.RawMessage(`{}`)
				case "noLease":
					request.Lease = nil
				case "wrongLease":
					request.Lease = &native.Lease{ID: "foreign", Generation: 1}
				}
				_, e := f.caller().Call(f.ctx, request)
				allowed := mode == "allowed" || method == "elements.valueMatches" && (mode == "noLease" || mode == "wrongLease")
				if allowed {
					if e != nil || f.calls != 1 {
						t.Fatal("qualified route rejected", e, f.calls)
					}
				} else if e == nil || f.calls != 0 {
					t.Fatal("unqualified route dispatched", e, f.calls)
				}
			})
		}
	}
}
func TestNativeControlSelectedTextUnknownRetainsBarrier(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	f.callErr = &native.NativeError{Code: "replacementUnknown", DispatchState: "unknown"}
	request := mutation(f)
	request.Method = "elements.replaceText"
	_, e := f.caller().Call(f.ctx, request)
	if e == nil || !f.manager.held.inhibited || f.calls != 1 {
		t.Fatal("selection-stage unknown lost barrier", e, f.calls)
	}
	before := f.calls
	if _, e = f.caller().Call(f.ctx, request); e == nil || f.calls != before {
		t.Fatal("unknown selected-text attempt allowedanotherinput", e)
	}
}

func TestNativeControlWindowKeyboardRequiresSessionOptinExactLeaseAndScope(t *testing.T) {
	for _, mode := range []string{"allowed", "noOptin", "foreign", "missingScope", "noLease", "wrongLease", "launchOnly"} {
		t.Run(mode, func(t *testing.T) {
			f := newControlFixture(t)
			f.manager.options.SemanticOnly = true
			f.manager.options.SessionKeyboard = true
			f.ready.SemanticQualified = true
			f.ready.SessionKeyboardQualified = true
			if mode == "launchOnly" {
				f.manager.options.LaunchOnly = true
				f.manager.options.SemanticOnly = false
				f.manager.options.SessionKeyboard = false
				f.ready.LaunchQualified = true
			}
			if mode == "noOptin" {
				f.manager.options.SessionKeyboard = false
			}
			f.admit(t)
			r := native.Request{Method: "windows.pressSessionKey", Params: json.RawMessage(`{"expectedApp":"com.fixture.app","pid":1,"processStartToken":"100:1","windowId":9625,"key":"Escape"}`), Lease: &native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}}
			switch mode {
			case "foreign":
				r.Params = json.RawMessage(`{"expectedApp":"com.foreign.app"}`)
			case "missingScope":
				r.Params = json.RawMessage(`{"bundleID":"com.fixture.app"}`)
			case "noLease":
				r.Lease = nil
			case "wrongLease":
				r.Lease.Generation++
			}
			_, e := f.caller().Call(f.ctx, r)
			if mode == "allowed" {
				if e != nil || f.calls != 1 {
					t.Fatal("qualified windowkey rejected", e, f.calls)
				}
			} else if e == nil || f.calls != 0 {
				t.Fatal("unqualified windowkey dispatched", mode, e, f.calls)
			}
		})
	}
}
