package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	get "github.com/viant/mechanize/data/chromeattemptbindingget"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
)

type hostReconnectFixture struct {
	host       *Host
	ctx        context.Context
	p          auth.Principal
	scope      chrome.ReconnectBindingScope
	descriptor chrome.BoundMutation
	read       func() []byte
	dispatches *atomic.Int32
}

func newHostReconnectFixture(t *testing.T, missing bool) *hostReconnectFixture {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(file))
	storage := t.TempDir()
	p, e := auth.NewPrincipal("fixture", "", "joined-reconnect", []string{"desktop:control"})
	if e != nil {
		t.Fatal(e)
	}
	p.ClientID = "original-tool-client"
	ctx, cancel := context.WithTimeout(auth.WithPrincipal(context.Background(), p), 60*time.Second)
	t.Cleanup(cancel)
	var b *durable.Builder
	var descriptor chrome.BoundMutation
	var commitErr error
	var dispatches atomic.Int32
	b, e = durable.New(durable.Options{SourceRoot: source, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) { return 1, nil }, PrepareStepAuthority: func(ctx context.Context, p auth.Principal, _ model.Step) (context.Context, int, error) {
		scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
		return scoped, 1, e
	}}, func(ctx context.Context, p auth.Principal, step model.Step, _ map[string]model.Value) (integration.StepResult, error) {
		dispatches.Add(1)
		intent, e := data.RequireCommittedStepIntent(ctx, p)
		if e != nil {
			return integration.StepResult{}, e
		}
		pinned := chrome.ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, BrokerEpoch: "old-broker", ChannelEpoch: "old-channel", ScopeHash: strings.Repeat("a", 64), Lease: chrome.Lease{ID: "lease", Generation: 1}}
		pinned.Document.Identity = chrome.Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "document", Generation: 1}
		id := data.ChromeAttemptBrowserIDV2(p.Namespace, p.ClientID, intent.AttemptID)
		command := chrome.Command{Action: step.Action, Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: &pinned.Lease, AttemptID: id, Locator: &chrome.Locator{Strategy: "id", Value: "save", Exact: true}}
		fingerprint, e := chrome.FingerprintMutationV2(command)
		if e != nil {
			return integration.StepResult{}, e
		}
		descriptor = chrome.BoundMutation{Action: step.Action, BrowserAttemptID: id, Identity: pinned.Document.Identity, BrokerEpoch: pinned.BrokerEpoch, ChannelEpoch: pinned.ChannelEpoch, ScopeHash: pinned.ScopeHash, ControlLease: pinned.Lease, Fingerprint: fingerprint}
		_, commitErr = commitChromeBinding(ctx, p, step, pinned, descriptor, b.InvokeCommittedComponent)
		if commitErr != nil {
			return integration.StepResult{}, commitErr
		}
		if missing {
			panic("fixture process loss before original outcome")
		}
		// The only executor is this inert fixture; recovery must never invoke it again.
		return integration.StepResult{DispatchState: "dispatched", VerificationState: "unknown", Value: &model.Value{Kind: model.StringValue, String: "FIXTURE-PRIVATE-RESULT-CANARY"}}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close(context.Background()) })
	execute := func(ctx context.Context, p auth.Principal, step model.Step, values map[string]model.Value) (result integration.StepResult, err error) {
		defer func() {
			if recover() != nil {
				err = errors.New("fixture stopped before outcome")
			}
		}()
		return b.Execute(ctx, p, step, values)
	}
	runtimeService, e := integration.NewWithOptions(execute, integration.Options{PreparePlan: b.PreparePlan, AttachInitialOperation: func(ctx context.Context, p auth.Principal, id string, revision int, session, operation string) error {
		_, e := b.AttachOperation(ctx, p, id, revision, session, operation)
		return e
	}})
	if e != nil {
		t.Fatal(e)
	}
	session, e := runtimeService.Open(ctx, "joined reconnect fixture")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { runtimeService.Close(ctx, session.SessionID) })
	plan, e := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
	if e != nil {
		t.Fatal(e)
	}
	plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"fixture": {Kind: model.StringValue, String: "joined-reconnect"}}
	operation, e := runtimeService.StartPlan(ctx, session.SessionID, *plan, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runtimeService.Wait(ctx, session.SessionID, operation.ID); e != nil {
		t.Fatal(e)
	}
	if commitErr != nil || dispatches.Load() != 1 || descriptor.BrowserAttemptID == "" {
		t.Fatal("actual durable binding fixture failed", commitErr)
	}
	scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	server, e := datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace, LeaseEpoch: 1})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { server.Shutdown(context.Background()) })
	read := func() []byte {
		in := &get.LoadChromeAttemptBindingInput{}
		in.SetNamespace(p.Namespace)
		in.SetClientID(p.ClientID)
		in.SetBrowserAttemptID(descriptor.BrowserAttemptID)
		value, e := server.InvokeComponent(scoped, exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/chromeattemptbindingget", Name: "LoadChromeAttemptBinding"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/chromeattemptbindingget"}}, Input: in})
		if e != nil {
			t.Fatal(e)
		}
		out := value.(*get.LoadChromeAttemptBindingOutput)
		if len(out.Data) != 1 {
			t.Fatal("original binding disappeared")
		}
		raw, _ := json.Marshal(out.Data[0])
		return raw
	}
	current := p
	current.ClientID = "current-native-client"
	return &hostReconnectFixture{host: &Host{durable: b}, ctx: auth.WithPrincipal(ctx, current), p: current, scope: chrome.ReconnectBindingScope{ProfileChannel: "profile", BrowserInstance: "browser", ScopeHash: strings.Repeat("a", 64), PendingDigest: strings.Repeat("b", 64)}, descriptor: descriptor, read: read, dispatches: &dispatches}
}
func TestHostChromeReconnectJoinedDatlyRetainsUnknownAndHoldsAdmissionThroughConsume(t *testing.T) {
	f := newHostReconnectFixture(t, false)
	before := f.read()
	if !strings.Contains(string(before), `"state":"unknown"`) {
		t.Fatal("original unverified fixture not retained")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.host.chromeReconnectBindings(f.ctx, f.p, f.scope, func(ctx context.Context) error {
			if auth.NativeHuman(ctx) {
				return fmt.Errorf("human impersonation")
			}
			return ctx.Err()
		}, func(rows []chrome.ReconnectBinding) error {
			if len(rows) != 1 || rows[0].AttemptID != f.descriptor.BrowserAttemptID || rows[0].Fingerprint != f.descriptor.Fingerprint.SHA256 || rows[0].DispatchState != "dispatched" || rows[0].Identity != f.descriptor.Identity {
				return errors.New("original dispatch projection changed")
			}
			raw, _ := json.Marshal(rows)
			if strings.Contains(string(raw), "CANARY") {
				return errors.New("result content escaped metadata projection")
			}
			close(entered)
			select {
			case <-release:
				return nil
			case <-f.ctx.Done():
				return f.ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case e := <-done:
		t.Fatal("callback failed before consumption", e)
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	competing := make(chan struct{})
	competitorDone := make(chan error, 1)
	go func() {
		competitorDone <- f.host.durable.WithChromeRetirementComponents(f.ctx, f.p, func(context.Context, durable.RetirementComponentInvoker) error { close(competing); return nil })
	}()
	select {
	case <-competing:
		t.Fatal("admission released before consume completed")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := <-competitorDone; e != nil {
		t.Fatal(e)
	}
	if string(before) != string(f.read()) || f.dispatches.Load() != 1 {
		t.Fatal("recovery changed original UNKNOWN/history or replayed input")
	}
	var revoked atomic.Bool
	consumed := false
	e := f.host.chromeReconnectBindings(f.ctx, f.p, f.scope, func(context.Context) error {
		if revoked.Load() {
			return auth.ErrUnauthorized
		}
		return nil
	}, func([]chrome.ReconnectBinding) error { consumed = true; revoked.Store(true); return nil })
	if !consumed || !errors.Is(e, auth.ErrUnauthorized) {
		t.Fatal("final native guard revocation ignored", e)
	}
	consumed = false
	e = f.host.chromeReconnectBindings(f.ctx, f.p, f.scope, func(context.Context) error { return auth.ErrUnauthorized }, func([]chrome.ReconnectBinding) error { consumed = true; return nil })
	if e == nil || consumed {
		t.Fatal("revoked admission reached consumer")
	}
	if string(before) != string(f.read()) || f.dispatches.Load() != 1 {
		t.Fatal("revocation mutated original history")
	}
}
func TestHostChromeReconnectJoinedDatlyReservedIntentStaysUnknownAcrossSourceDecisions(t *testing.T) {
	f := newHostReconnectFixture(t, true)
	before := f.read()
	var saved struct {
		Effect struct {
			State    string  `json:"state"`
			Revision int     `json:"revision"`
			Evidence *string `json:"evidenceJson"`
		} `json:"effect"`
		Outcomes []json.RawMessage `json:"outcomes"`
	}
	if json.Unmarshal(before, &saved) != nil || saved.Effect.State != "intent" || saved.Effect.Revision != 1 || saved.Effect.Evidence != nil || len(saved.Outcomes) != 0 {
		t.Fatal("fixture is not an untouched reserved intent")
	}
	sourcePresent := errors.New("fixture exact source still present")
	for _, absent := range []bool{false, true} {
		consumed := false
		started := time.Now()
		err := f.host.chromeReconnectBindings(f.ctx, f.p, f.scope, func(context.Context) error { return nil }, func(rows []chrome.ReconnectBinding) error {
			consumed = true
			if len(rows) != 1 || rows[0].DispatchState != "unknown" || rows[0].AttemptID != f.descriptor.BrowserAttemptID || rows[0].Fingerprint != f.descriptor.Fingerprint.SHA256 || rows[0].Identity != f.descriptor.Identity {
				return errors.New("reserved binding lost original UNKNOWN identity")
			}
			// Source presence/absence is independently proved by the native/worker
			// consumer; this fixture exercises both decisions, never inventing receipt
			// certainty or resolving the original durable intent.
			if !absent {
				return sourcePresent
			}
			return nil
		})
		t.Logf("source_absent=%t callback_ms=%d", absent, time.Since(started).Milliseconds())
		if !consumed || (!absent && !errors.Is(err, sourcePresent)) || (absent && err != nil) {
			t.Fatalf("source decision not preserved absent=%t: %v", absent, err)
		}
		if string(before) != string(f.read()) || f.dispatches.Load() != 1 {
			t.Fatal("source decision resolved intent, changed history or replayed input")
		}
	}
}

func TestHostChromeReconnectActualProviderIncludesOriginalEpochOmittedFromLineageFences(t *testing.T) {
	f := newHostReconnectFixture(t, false)
	before := f.read()
	// A reference can omit historical fences. The actual provider must still
	// return the original client's epoch from its exact all-epochs Datly snapshot.
	f.scope.Fences = []chrome.ReconnectFence{{BrokerEpoch: "unrelated-current", ChannelEpoch: "unrelated-current", ScopeHash: f.scope.ScopeHash}}
	consumed := false
	err := f.host.chromeReconnectBindings(f.ctx, f.p, f.scope, func(ctx context.Context) error { return ctx.Err() }, func(rows []chrome.ReconnectBinding) error {
		consumed = true
		if len(rows) != 1 || rows[0].AttemptID != f.descriptor.BrowserAttemptID || rows[0].Fence.BrokerEpoch == "unrelated-current" || rows[0].Fence.ChannelEpoch == "unrelated-current" {
			return errors.New("original epoch excluded by supplied fence subset")
		}
		return nil
	})
	if err != nil || !consumed {
		t.Fatal("complete scope snapshot failed", err)
	}
	if string(before) != string(f.read()) || f.dispatches.Load() != 1 {
		t.Fatal("snapshot changed original outcome or replayed input")
	}
}
