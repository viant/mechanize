package host

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	automation "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

type consentScopeMarker struct{}

func TestConsentBrokerRetainsTrustedScopeAndRejectsForeignNamespace(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "scope-owner", []string{"desktop:control"})
	p.ClientID = "client"
	b, err := NewConsentBroker(ConsentBrokerOptions{Invoke: func(context.Context, auth.Principal, exec.ComponentRequest) (any, error) {
		t.Fatal("scope check invoked database")
		return nil, nil
	}, Enrolled: func(context.Context, auth.Principal) (User, error) { return User{}, nil }, SessionOwned: func(context.Context, auth.Principal, string) error { return nil }, Policy: func(context.Context, auth.Principal, consent.Scope, []consent.Mode, int) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	base := auth.WithPrincipal(context.WithValue(context.Background(), consentScopeMarker{}, "private-marker"), p)
	binding := auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "scope proof"}
	base = auth.WithConsentBinding(base, binding)
	for _, epoch := range []int{0, 7, 42} {
		ctx, _ := data.WithScope(base, data.Scope{Namespace: p.Namespace, LeaseEpoch: epoch})
		scoped, _, err := b.bound(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := data.RequireScope(scoped, p.Namespace)
		if err != nil || got.LeaseEpoch != epoch {
			t.Fatal("trusted executor epoch changed", got, err)
		}
		actor, err := auth.FromContext(scoped)
		if err != nil || actor.ClientID != p.ClientID {
			t.Fatal("actor lost")
		}
		gotBinding, ok := auth.ConsentBindingFromContext(scoped)
		if !ok || gotBinding != binding || scoped.Value(consentScopeMarker{}) != "private-marker" {
			t.Fatal("context binding lost")
		}
	}
	unscoped, _, err := b.bound(base, p)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := data.CurrentScope(unscoped)
	if scope.Namespace != p.Namespace || scope.LeaseEpoch != 0 {
		t.Fatal("unscoped admission must use zero epoch")
	}
	other, _ := auth.NewPrincipal("fixture", "", "foreign", nil)
	foreign, _ := data.WithScope(base, data.Scope{Namespace: other.Namespace, LeaseEpoch: 7})
	if _, _, err = b.bound(foreign, p); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatal("foreign scope replaced with actor scope", err)
	}
}

func TestRealConsentLeasePreservesWebRendererAuthorityAndRevocation(t *testing.T) {
	f := newWebControlFixture(t)
	f.principal.ClientName = "Scope fixture client"
	f.principal.Scopes = append(f.principal.Scopes, "consent:admin")
	f.ctx = auth.WithPrincipal(f.ctx, f.principal)
	_, file, _, _ := runtime.Caller(0)
	source := filepath.Dir(filepath.Dir(file))
	initial, _ := data.WithScope(f.ctx, data.Scope{Namespace: f.principal.Namespace})
	server, err := datahost.Open(initial, source, t.TempDir(), data.Scope{Namespace: f.principal.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	binding, _ := auth.ConsentBindingFromContext(f.ctx)
	h := &Host{users: map[string]User{f.principal.Namespace: {Subject: f.principal.Subject, DesktopAccess: true}}}
	h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: func(ctx context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
		return server.InvokeComponent(ctx, r)
	}, Enrolled: h.enrolled, SessionOwned: func(_ context.Context, p auth.Principal, id string) error {
		if p.Namespace != f.principal.Namespace || id != binding.SessionID {
			return auth.ErrUnauthorized
		}
		return nil
	}, Policy: h.ConsentPolicy})
	if err != nil {
		t.Fatal(err)
	}
	in := consent.RequestInput{Scope: consent.Scope{Kind: "origin", Origin: f.step.Target.Surface.Origin}, Modes: []consent.Mode{consent.Control}, Purpose: binding.Purpose, DurationSeconds: 120}
	request, err := h.consent.Request(f.ctx, f.principal, binding.SessionID, in)
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
	binding.GrantID = grant.ID
	f.ctx = auth.WithConsentBinding(f.ctx, binding)
	// Warm the generated authorization component before Endly's short inert callback.
	warm, err := h.AuthorizeOperation(f.ctx, f.principal, f.step.Target.Surface, true, consent.Control)
	if err != nil {
		t.Fatal(err)
	}
	warm.Release()
	f.manager.options.Authorize = func(ctx context.Context, p auth.Principal, s model.Surface) (*consent.Lease, error) {
		return h.AuthorizeOperation(ctx, p, s, true, consent.Control)
	}
	withWebExecution(t, f, func(ctx context.Context, p auth.Principal, step model.Step) {
		prepared := prepareWeb(t, f, ctx, p, step)
		meta, ok := automation.ExecutionFromContext(prepared)
		if !ok {
			t.Fatal("Endly metadata absent")
		}
		f.manager.options.ExecutePinned = func(dispatched context.Context, actor auth.Principal, _ model.Step, _ map[string]model.Value, _ WebControlAuthority) (automation.StepResult, error) {
			scope, err := data.RequireScope(dispatched, p.Namespace)
			gotMeta, hasMeta := automation.ExecutionFromContext(dispatched)
			gotBinding, hasBinding := auth.ConsentBindingFromContext(dispatched)
			if err != nil || scope.LeaseEpoch != 7 || actor.ClientID != p.ClientID || !hasMeta || gotMeta != meta || !hasBinding || gotBinding != binding {
				t.Error("consent lease changed admitted renderer/actor/metadata/binding")
			}
			f.dispatches++
			return automation.StepResult{DispatchState: "dispatched"}, nil
		}
		result, err := f.manager.Execute(prepared, p, step, nil)
		if err != nil || result.DispatchState != "dispatched" {
			t.Errorf("real consent blocked inert pinned dispatch: %+v %v", result, err)
		}
	})
	if f.dispatches != 1 {
		t.Fatal("wrong dispatch count", f.dispatches)
	}
	scoped, _ := data.WithScope(f.ctx, data.Scope{Namespace: f.principal.Namespace, LeaseEpoch: 7})
	active, err := h.AuthorizeOperation(scoped, f.principal, f.step.Target.Surface, true, consent.Control)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Release()
	if scope, err := data.RequireScope(active.Context, f.principal.Namespace); err != nil || scope.LeaseEpoch != 7 {
		t.Fatal("active consent lease lost epoch", scope, err)
	}
	revoke, _ := json.Marshal(map[string]any{"grantID": grant.ID})
	if _, err = h.consent.NativeRPC(human, "revoke", revoke); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active.Context.Done():
	case <-time.After(time.Second):
		t.Fatal("scope preservation broke revocation cancellation")
	}
	if _, err = h.AuthorizeOperation(scoped, f.principal, f.step.Target.Surface, true, consent.Control); err == nil {
		t.Fatal("revoked grant admitted new operation")
	}
}
