package durable

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestPreflightLifecycleRechecksChildrenAfterReadBeforeCAS(t *testing.T) {
	base, old := privateActor(t)
	old.ClientID = "controller:" + strings.Repeat("a", 64)
	old.ClientName = "Old controller"
	ctx := auth.WithPrincipal(base, old)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "original-session", GrantID: "original-grant", Purpose: "original login"})
	_, file, _, _ := runtime.Caller(0)
	b, e := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("lifecycle acquired input fence")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("lifecycle dispatched")
		return integration.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(context.Background())
	allow := func(c context.Context) error { return c.Err() }
	now := time.Now().UTC().Format(time.RFC3339Nano)
	prep := data.CredentialPreparationRecord{Namespace: old.Namespace, ClientID: old.ClientID, SessionID: "original-session", GrantID: "original-grant", PurposeHash: data.CredentialDeliveryPurposeHash("original login"), PreparationID: strings.Repeat("b", 64), Origin: "https://fixture.invalid", SelectedRevision: strings.Repeat("c", 64), ProtectionState: "held", Revision: 1, CreatedAt: now}
	e = b.WithCredentialDeliveryComponents(ctx, old, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		bound, stop, e := data.WithCredentialPreparationAuthority(held, prep, allow)
		if e != nil {
			return e
		}
		defer stop()
		return b.ReserveCredentialPreparation(bound, old)
	})
	if e != nil {
		t.Fatal(e)
	}
	current := old
	current.ClientID = "successor"
	current.ClientName = "Successor"
	next := auth.WithConsentBinding(auth.WithPrincipal(base, current), auth.ConsentBinding{SessionID: "current-session", GrantID: "current-grant", Purpose: "current login"})
	scope := data.CredentialProtectionScopeRecord{Namespace: prep.Namespace, ClientID: prep.ClientID, PreparationID: prep.PreparationID, Origin: prep.Origin}
	guard := func(c context.Context) error {
		p, e := auth.FromContext(c)
		if e != nil || p.ClientID != current.ClientID {
			t.Fatal("cleanup forged original actor")
		}
		return c.Err()
	}
	var stale data.CredentialPreparationRecord
	e = b.WithCredentialDeliveryComponents(next, current, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		bound, stop, e := data.WithCredentialPreflightLifecycleAuthority(held, scope, guard)
		if e != nil {
			return e
		}
		defer stop()
		var children []data.CredentialDeliveryRecord
		stale, children, e = b.LoadCredentialRecovery(bound, current, prep.PreparationID)
		if e != nil || stale != prep || len(children) != 0 {
			t.Fatal("initial typed zero-child read failed", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// A distinct original-owner transaction commits UNKNOWN after the earlier
	// zero-child read. This uses the actual typed reserve path, never fixture SQL.
	child := data.CredentialDeliveryRecord{Namespace: old.Namespace, ClientID: old.ClientID, SessionID: prep.SessionID, GrantID: prep.GrantID, SelectionID: prep.PreparationID, SelectedRevision: prep.SelectedRevision, PurposeHash: prep.PurposeHash, Origin: prep.Origin, AttemptID: strings.Repeat("d", 64), ProfileChannel: "profile", BrowserInstance: "browser", DocumentID: "document", DocumentGeneration: 1, TabID: 7, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("e", 64), RendererLeaseID: "lease", RendererLeaseGeneration: 1, ChromeStartToken: "123:456", NativeHostStartToken: "234:567", DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: now, UpdatedAt: now}
	e = b.WithCredentialDeliveryComponents(ctx, old, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		bound, stop, e := data.WithCredentialDeliveryAuthority(held, data.CredentialDeliveryAuthority{Record: child}, allow)
		if e != nil {
			return e
		}
		defer stop()
		return b.ReserveCredentialDelivery(bound, old)
	})
	if e != nil {
		t.Fatal(e)
	}
	e = b.WithCredentialDeliveryComponents(next, current, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		seal, stop, e := data.WithCredentialPreflightLifecycleAuthority(held, scope, guard)
		if e != nil {
			return e
		}
		defer stop()
		clean, release, e := data.WithCredentialPreflightCleanupAuthority(seal, stale, guard)
		if e != nil {
			return e
		}
		defer release()
		closed := stale
		closed.ProtectionState = "closed"
		closed.Revision++
		bound, revoke, e := data.WithCredentialPreparationAuthority(clean, closed, guard)
		if e != nil {
			return e
		}
		defer revoke()
		if e = b.CloseCredentialPreparation(bound, current); e == nil {
			t.Fatal("stale zero-child snapshot closed parent with new UNKNOWN child")
		}
		actual, children, e := b.LoadCredentialRecovery(seal, current, prep.PreparationID)
		if e != nil || actual != prep || len(children) != 1 || children[0] != child {
			t.Fatal("failed CAS changed immutable parent/UNKNOWN receipt", e)
		}
		if _, _, e = data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Record: child}, guard); e == nil {
			t.Fatal("preflight seal granted original delivery")
		}
		if e = b.ReserveCredentialPreparation(bound, current); e == nil {
			t.Fatal("preflight seal granted reserve")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
