package host

import (
	"context"
	"encoding/json"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNativeConsentDomainHostDatlyPreservesBrowserSuspension(t *testing.T) {
	f := newControlFixture(t)
	f.principal.ClientID = "fixture-agent"
	f.principal.ClientName = "Fixture Agent"
	f.principal.Scopes = append(f.principal.Scopes, "consent:admin")
	f.ctx = auth.WithPrincipal(context.Background(), f.principal)
	h := &Host{users: map[string]User{f.principal.Namespace: {DesktopAccess: true, NativeBundles: f.enrolled}}}
	f.alive = false
	f.options.EnrolledScope = func(context.Context, auth.Principal) (session.Scope, error) {
		return session.Scope{AllApplications: true}, nil
	}
	f.ready.AllApplicationsQualified = true
	f.ready.QualifiedBundles = nil
	historical := session.Lease{ID: "historical", Generation: 77, Owner: f.principal.Namespace, Scope: session.Scope{AllowedBundles: f.enrolled}}
	raw, _ := json.Marshal(map[string]any{"generation": 77, "lease": historical, "helper": f.identity, "inputProfile": "raw", "lastCleanup": session.CleanupReport{UnknownInputs: true, BusinessOutcomeUnknown: true}})
	if err := os.WriteFile(f.options.LockPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	factory := f.options.HelperFactory
	f.options.HelperFactory = func(c context.Context, o native.Options) (NativeControlHelper, error) {
		f.alive = true
		f.identity.StartToken = "new-helper"
		return factory(c, o)
	}
	if err := h.configureNativeControl(f.owner, Config{NativeHelper: f.options.HelperPath}, HostOptions{NativeControl: &f.options}); err != nil {
		t.Fatal(err)
	}
	defer h.nativeControl.Close(context.Background())
	reader := &cleanupProofCaller{inventory: `{"complete":true,"apps":[{"bundleID":"com.google.Chrome"}]}`}
	h.nativeClient = reader
	_, file, _, _ := runtime.Caller(0)
	scope := data.Scope{Namespace: f.principal.Namespace}
	scoped, err := data.WithScope(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(scoped, filepath.Dir(filepath.Dir(file)), t.TempDir(), scope)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	options := ConsentBrokerOptions{Invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
		return server.InvokeComponent(c, r)
	}, Enrolled: h.enrolled, Policy: h.ConsentPolicy, SessionOwned: func(_ context.Context, p auth.Principal, id string) error {
		if p.ClientID != f.principal.ClientID || id != "fixture-session" {
			return auth.ErrUnauthorized
		}
		return nil
	}, RecoverCleanup: h.proveConsentCleanup, RecoverNativeCleanup: h.proveNativeConsentCleanup}
	h.consent, err = NewConsentBroker(options)
	if err != nil {
		t.Fatal(err)
	}
	in := consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Observe, consent.Control}, Purpose: "fixture editing", DurationSeconds: 60}
	request, err := h.consent.Request(f.ctx, f.principal, "fixture-session", in)
	if err != nil {
		t.Fatal(err)
	}
	human, err := auth.WithNativeHuman(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
	value, err := h.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	grant := value.(*consent.Grant)
	bound := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{GrantID: grant.ID, SessionID: "fixture-session", Purpose: in.Purpose})
	op := consent.Operation{GrantID: grant.ID, SessionID: "fixture-session", Scope: consent.Scope{Kind: "application", BundleID: "com.fixture.app"}, Mode: consent.Control, Purpose: in.Purpose}
	old, err := h.consent.Authorize(bound, f.principal, op)
	if err != nil {
		t.Fatal(err)
	}
	internal, service, err := h.consent.bound(bound, f.principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReportDispatchCleanupUnknown(internal, grant.ID); err != nil {
		t.Fatal(err)
	}
	old.Release()
	// A new broker uses the same Datly store and historical physical fence.
	h.consent, err = NewConsentBroker(options)
	if err != nil {
		t.Fatal(err)
	}
	newSession := auth.WithConsentBinding(f.ctx, auth.ConsentBinding{SessionID: "fixture-session", Purpose: in.Purpose})
	lease, err := h.AuthorizeOperation(newSession, f.principal, model.Surface{Kind: "native", BundleID: "com.fixture.app"}, true, consent.Control)
	if err != nil {
		t.Fatal("native cleanup remained coupled to running Chrome", err)
	}
	binding, ok := auth.ConsentBindingFromContext(lease.Context)
	if !ok || binding.GrantID != grant.ID {
		t.Fatal("retained grant binding lost")
	}
	lease.Release()
	if f.starts != 1 || f.calls != 0 {
		t.Fatal("native proof failed or replayed input", f.starts, f.calls)
	}
	for _, method := range reader.calls {
		if method == "apps.list" {
			t.Fatal("native operation required browser death")
		}
	}
	if _, err = h.AuthorizeOperation(newSession, f.principal, model.Surface{Kind: "web", Origin: "https://fixture.invalid"}, true, consent.Control); err == nil {
		t.Fatal("native cleanup restored unproved web authority")
	}
	internal, service, err = h.consent.bound(human, f.principal)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := service.ListGrants(internal)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].RevocationState != consent.CleanupUnknown {
		t.Fatal("durable consent suspension changed")
	}
}
