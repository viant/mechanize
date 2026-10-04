package host

import (
	"context"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
	"path/filepath"
	"runtime"
	"testing"
)

func TestApplicationAccessUpdateCancelsAndFencesAdmissions(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control", "consent:admin"})
	p.ClientID = "agent"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx, _ = data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	human, err := auth.WithNativeHuman(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, file, _, _ := runtime.Caller(0)
	server, err := datahost.Open(ctx, filepath.Dir(filepath.Dir(file)), t.TempDir(), data.Scope{Namespace: p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown(context.Background())
	service := &applicationAccessService{invoke: func(c context.Context, _ auth.Principal, r exec.ComponentRequest) (any, error) {
		return server.InvokeComponent(c, r)
	}, enrolled: func(c context.Context, actor auth.Principal) (User, error) {
		actual, e := auth.FromContext(c)
		if e != nil || actual.Namespace != p.Namespace || actor.Namespace != p.Namespace {
			return User{}, auth.ErrUnauthorized
		}
		return User{DesktopAccess: true}, nil
	}}
	calculator := consent.Scope{Kind: "application", BundleID: "com.apple.calculator"}
	gate, generation, err := service.admission(ctx, p, calculator, consent.Control)
	if err != nil {
		t.Fatal(err)
	}
	stopped := false
	base, cancel := context.WithCancel(ctx)
	defer cancel()
	lease, err := gate.retain(generation, &consent.Lease{Context: base, Release: func() { stopped = true; cancel() }})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	policy := data.ApplicationPolicy{DesktopWide: true, Applications: []data.ApplicationPolicyRule{{BundleID: "com.apple.calculator", DisplayName: "Calculator", Modes: []string{}}}}
	if _, err = service.update(ctx, p, 0, policy); err == nil {
		t.Fatal("requester edited application policy")
	}
	saved, err := service.update(human, p, 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Revision != 1 || saved.Policy.Allows(calculator.BundleID, "control") {
		t.Fatal("deny rule not persisted")
	}
	if lease.Context.Err() == nil || stopped {
		t.Fatal("policy update must cancel admission without inventing cleanup completion")
	}
	if _, _, err = service.admission(ctx, p, calculator, consent.Control); err == nil {
		t.Fatal("disabled application was admitted")
	}
	if _, _, err = service.admission(ctx, p, consent.Scope{Kind: "application", BundleID: "com.apple.finder"}, consent.Control); err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.admission(ctx, p, consent.Scope{Kind: "desktop"}, consent.Record); err == nil {
		t.Fatal("desktop recording bypassed excluded app")
	}
	released := false
	if _, err = gate.retain(generation, &consent.Lease{Context: ctx, Release: func() { released = true }}); err == nil || !released {
		t.Fatal("stale in-flight admission bypassed updated policy")
	}
	if _, err = service.update(human, p, 0, data.ApplicationPolicy{DesktopWide: true}); err == nil {
		t.Fatal("stale policy edit overwrote deny")
	}
	current, err := service.snapshot(human, p)
	if err != nil || current.Revision != 1 || current.Policy.Allows(calculator.BundleID, "control") {
		t.Fatalf("stale update changed state: %+v %v", current, err)
	}
	lease.Release()
	if !stopped {
		t.Fatal("confirmed cleanup did not release underlying lease")
	}
}
