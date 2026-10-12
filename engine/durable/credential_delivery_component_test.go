package durable

import (
	"context"
	"github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCredentialDeliveryComponentExactExposure(t *testing.T) {
	for _, entry := range []struct{ pkg, name, method string }{{"credentialpreparationreserve", "CredentialPreparationReserve", "POST"}, {"credentialpreparationget", "CredentialPreparationGet", "GET"}, {"credentialdeliveryreserve", "CredentialDeliveryReserve", "POST"}, {"credentialdeliveryget", "CredentialDeliveryGet", "GET"}, {"credentialdeliveryfinish", "CredentialDeliveryFinish", "PATCH"}} {
		base := exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/" + entry.pkg, Name: entry.name}, Route: spec.RouteRef{Method: entry.method, Path: "/internal/data/" + entry.pkg}}}
		if !credentialDeliveryComponentAllowed(base) {
			t.Fatal("intended generated contract rejected")
		}
		for _, field := range []string{"name", "scope", "method", "path", "kind"} {
			bad := base
			switch field {
			case "name":
				bad.Target.Component.Name = "Other"
			case "scope":
				bad.Target.Component.Scope += "other"
			case "method":
				bad.Target.Route.Method = "DELETE"
			case "path":
				bad.Target.Route.Path += "other"
			case "kind":
				bad.Target.Component.Kind = "other"
			}
			if credentialDeliveryComponentAllowed(bad) {
				t.Fatal("forged target accepted", field)
			}
		}
	}
}
func TestCredentialDeliveryComponentCannotUseOrdinaryUnheldContext(t *testing.T) {
	ctx, p := privateActor(t)
	b := &Builder{}
	req := exec.ComponentRequest{Target: exec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: "github.com/viant/mechanize/data/credentialdeliveryget", Name: "CredentialDeliveryGet"}, Route: spec.RouteRef{Method: "GET", Path: "/internal/data/credentialdeliveryget"}}}
	if _, err := b.invokeCredentialDeliveryComponent(ctx, p, req); err == nil {
		t.Fatal("unheld invocation accepted")
	}
	held, revoke := b.withHeldUserLock(ctx, p, &userHost{})
	defer revoke()
	called := false
	if err := b.WithCredentialDeliveryComponents(held, p, func(context.Context, CredentialDeliveryComponentInvoker) error { called = true; return nil }); err == nil || called {
		t.Fatal("nested callback accepted")
	}
}

func TestCredentialDeliveryWrapperCommitsReadsAndCannotEscape(t *testing.T) {
	ctx, p := privateActor(t)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "login"})
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	b, err := New(Options{SourceRoot: root, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("private reservation requested ordinary execution lease")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("database wrapper dispatched browser input")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())
	now := time.Now().UTC().Format(time.RFC3339Nano)
	r := data.CredentialDeliveryRecord{PurposeHash: data.CredentialDeliveryPurposeHash("login"), Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "session", GrantID: "grant", AttemptID: strings.Repeat("a", 64), SelectionID: strings.Repeat("b", 64), SelectedRevision: strings.Repeat("c", 64), Origin: "https://bank.invalid", ProfileChannel: "profile", BrowserInstance: "browser", DocumentID: "doc", DocumentGeneration: 1, TabID: 7, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("d", 64), RendererLeaseID: "lease", RendererLeaseGeneration: 1, ChromeStartToken: "123:1", NativeHostStartToken: "123:2", DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: now, UpdatedAt: now}
	if blocked, e := b.CredentialDeliveryBlocked(ctx, p); e != nil || blocked {
		t.Fatal("empty fixture reported blocked", e)
	}
	var escaped context.Context
	err = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		prep := data.CredentialPreparationRecord{Namespace: r.Namespace, ClientID: r.ClientID, SessionID: r.SessionID, PreparationID: r.SelectionID, GrantID: r.GrantID, PurposeHash: r.PurposeHash, Origin: r.Origin, SelectedRevision: r.SelectedRevision, ProtectionState: "held", Revision: 1, CreatedAt: r.CreatedAt}
		preCtx, preRevoke, e := data.WithCredentialPreparationAuthority(held, prep, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		defer preRevoke()
		if e = b.ReserveCredentialPreparation(preCtx, p); e != nil {
			return e
		}
		bound, revoke, e := data.WithCredentialDeliveryAuthority(held, data.CredentialDeliveryAuthority{Record: r}, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		defer revoke()
		escaped = bound
		if e = b.ReserveCredentialDelivery(bound, p); e != nil {
			return e
		}
		if blocked, e := b.CredentialDeliveryBlocked(bound, p); e != nil || !blocked {
			t.Fatal("held reservation not seen by barrier", e)
		}
		actual, e := b.ReadCredentialDelivery(bound, p)
		if e != nil || actual != r {
			t.Fatal("confirmed reservation readback differs")
		}
		if e = b.ReserveCredentialDelivery(bound, p); e == nil {
			t.Fatal("same private reservation replay accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if blocked, e := b.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		t.Fatal("barrier disappeared outside delivery callback", e)
	}
	if _, err = b.ReadCredentialDelivery(escaped, p); err == nil {
		t.Fatal("private wrapper escaped held callback")
	}
	if e := b.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	reopened := &Builder{options: Options{SourceRoot: root, StorageRoot: storage, MaxUsers: 1}, users: map[string]*userHost{}}
	defer reopened.Close(context.Background())
	if blocked, e := reopened.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		t.Fatal("restart lost durable exposure barrier", e)
	}
	other := p
	other.ClientID = "other-client"
	if blocked, e := reopened.CredentialDeliveryBlocked(auth.WithPrincipal(ctx, other), other); e != nil || !blocked {
		t.Fatal("namespace barrier did not cover other client", e)
	}

}
