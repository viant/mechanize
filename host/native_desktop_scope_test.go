package host

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/session"
)

func TestNativeDesktopScopeCrossAppSameEpochAndFreshEnrollment(t *testing.T) {
	_, f := launchOnlyFixture(t)
	enrolled := session.Scope{AllApplications: true}
	f.manager.options.Enrolled = nil
	f.manager.options.EnrolledScope = func(context.Context, auth.Principal) (session.Scope, error) { return enrolled, nil }
	f.ready.AllApplicationsQualified = true
	f.ready.QualifiedBundles = nil
	admission, err := f.manager.AdmitScope(f.ctx, f.principal, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	lease := native.Lease{ID: f.manager.held.lease.ID, Generation: f.manager.held.lease.Generation}
	for _, bundle := range []string{"com.apple.mail", "com.apple.TextEdit", "com.new.installation"} {
		params, _ := json.Marshal(map[string]any{"expectedApp": bundle})
		if _, err := f.caller().Call(f.ctx, native.Request{Method: "app.launch", Params: params, Lease: &lease}); err != nil {
			t.Fatalf("new application inventory ceiling %s: %v", bundle, err)
		}
	}
	again, err := f.manager.AdmitScope(f.ctx, f.principal, session.Scope{AllApplications: true})
	if err != nil || again.Epoch != admission.Epoch || f.starts != 1 || f.calls != 3 {
		t.Fatalf("desktop grant changedepoch: %+v %v", again, err)
	}
	if _, err = f.manager.Admit(f.ctx, f.principal, []string{"com.apple.mail"}); err == nil {
		t.Fatal("silently changed whole scope")
	}
	other, _ := auth.NewPrincipal("issuer", "tenant", "other", []string{"desktop:control"})
	if _, err = f.manager.AdmitScope(auth.WithPrincipal(context.Background(), other), other, enrolled); !errors.Is(err, session.ErrContended) {
		t.Fatalf("desktop became principal-local: %v", err)
	}
	for _, target := range []string{"*", "/Applications/Mail.app"} {
		params, _ := json.Marshal(map[string]any{"expectedApp": target})
		if _, err = f.caller().Call(f.ctx, native.Request{Method: "app.launch", Params: params, Lease: &lease}); err == nil {
			t.Fatalf("unsafe exacttarget accepted %q", target)
		}
	}
	stale := lease
	stale.Generation++
	if _, err = f.caller().Call(f.ctx, native.Request{Method: "app.launch", Params: json.RawMessage(`{"expectedApp":"com.apple.mail"}`), Lease: &stale}); err == nil {
		t.Fatal("stale desktop epoch dispatched")
	}
	enrolled = session.Scope{AllowedBundles: []string{"com.apple.mail"}}
	if _, err = f.caller().Call(f.ctx, native.Request{Method: "app.launch", Params: json.RawMessage(`{"expectedApp":"com.apple.mail"}`), Lease: &lease}); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("changed operator authority retainedfullscope: %v", err)
	}
	if f.calls != 3 {
		t.Fatal("denied desktop request reachedhelper")
	}
}
func TestNativeDesktopScopeNeedsExplicitQualificationAndEnrollment(t *testing.T) {
	for _, test := range []string{"enrollment", "qualification", "mixed"} {
		t.Run(test, func(t *testing.T) {
			_, f := launchOnlyFixture(t)
			if test != "enrollment" {
				f.manager.options.EnrolledScope = func(context.Context, auth.Principal) (session.Scope, error) {
					return session.Scope{AllApplications: true}, nil
				}
			}
			if test == "mixed" {
				f.ready.AllApplicationsQualified = true
			}
			if _, err := f.manager.AdmitScope(f.ctx, f.principal, session.Scope{AllApplications: true}); err == nil {
				t.Fatal("legacy bundle readiness minted desktop authority")
			}
			if f.calls != 0 {
				t.Fatal("unqualified helper dispatched")
			}
		})
	}
}
