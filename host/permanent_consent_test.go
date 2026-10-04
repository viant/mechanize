package host

import (
	"context"
	"encoding/json"
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

func TestPermanentHostApprovalSurvivesSessionAndBrokerRestart(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:observe", "desktop:control", "consent:admin"})
	p.ClientID = "trusted-agent"
	p.ClientName = "Trusted agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	scoped, err := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	storage := t.TempDir()
	source := filepath.Dir(filepath.Dir(file))
	server, err := datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Shutdown(context.Background()) }()
	newHost := func() *Host {
		h := &Host{users: map[string]User{p.Namespace: {Subject: p.Subject, DesktopAccess: true}}}
		h.Runtime, err = automation.New(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (automation.StepResult, error) {
			t.Error("authorization fixture must not dispatch")
			return automation.StepResult{}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		h.consent, err = NewConsentBroker(ConsentBrokerOptions{Invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
			return server.InvokeComponent(c, r)
		}, Enrolled: h.enrolled, SessionOwned: h.Runtime.CheckSession, Policy: h.ConsentPolicy})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	first := newHost()
	session, err := first.Runtime.Open(ctx, "initial trusted session")
	if err != nil {
		t.Fatal(err)
	}
	request, err := first.consent.Request(ctx, p, session.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "desktop"}, Modes: []consent.Mode{consent.Observe, consent.Control}, Purpose: "Interactive desktop", DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	decision, _ := json.Marshal(map[string]any{"requestID": request.ID, "decision": consent.AllowUntilRevoked})
	if _, err = first.consent.NativeRPC(ctx, "decide", decision); err == nil {
		t.Fatal("requester self-approved permanent trust")
	}
	value, err := first.consent.NativeRPC(human, "decide", decision)
	if err != nil {
		t.Fatal(err)
	}
	grant := value.(*consent.Grant)
	if !grant.Permanent || !grant.ExpiresAt.Equal(time.Unix(0, 0)) {
		t.Fatalf("permanent wire contract: %+v", grant)
	}
	if err = first.Runtime.Close(ctx, session.SessionID); err != nil {
		t.Fatal(err)
	}
	if err = server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	server, err = datahost.Open(scoped, source, storage, data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the broker registry. The original runtime session no longer exists.
	second := newHost()
	var leases []*consent.Lease
	for _, purpose := range []string{"Open Calculator", "Find a document"} {
		s, err := second.Runtime.Open(ctx, purpose)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Runtime.Close(ctx, s.SessionID)
		bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: s.SessionID, Purpose: purpose})
		lease, err := second.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.apple.calculator"}, true, consent.Control)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		if _, bounded := lease.Context.Deadline(); bounded {
			t.Fatal("permanent grant acquired an expiry")
		}
		binding, _ := auth.ConsentBindingFromContext(lease.Context)
		if binding.GrantID != grant.ID || binding.SessionID != s.SessionID || binding.Purpose != purpose {
			t.Fatal("automatic grant binding lost current operation context")
		}
		leases = append(leases, lease)
	}
	other := p
	other.ClientID = "other-agent"
	other.ClientName = "Other agent"
	otherCtx := auth.WithPrincipal(context.Background(), other)
	otherSession, err := second.Runtime.Open(otherCtx, "other client")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Runtime.Close(otherCtx, otherSession.SessionID)
	otherCtx = auth.WithConsentBinding(otherCtx, auth.ConsentBinding{SessionID: otherSession.SessionID, Purpose: "Open Calculator"})
	if _, err = second.AuthorizeOperation(otherCtx, other, model.Surface{Kind: "native", BundleID: "com.apple.calculator"}, true, consent.Control); err == nil {
		t.Fatal("permanent trust crossed client identity")
	}
	revoke, _ := json.Marshal(map[string]any{"grantID": grant.ID})
	if _, err = second.consent.NativeRPC(human, "revoke", revoke); err != nil {
		t.Fatal(err)
	}
	for _, lease := range leases {
		select {
		case <-lease.Context.Done():
		case <-time.After(time.Second):
			t.Fatal("revoke did not stop every session")
		}
		lease.Release()
	}
	if _, err = second.consent.NativeRPC(human, "revoke", revoke); err != nil {
		t.Fatal(err)
	}
	s, err := second.Runtime.Open(ctx, "after revoke")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Runtime.Close(ctx, s.SessionID)
	bound := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: s.SessionID, Purpose: "Open Calculator"})
	if _, err = second.AuthorizeOperation(bound, p, model.Surface{Kind: "native", BundleID: "com.apple.calculator"}, true, consent.Control); err == nil {
		t.Fatal("revoked trust was reused")
	}
}
