package durable

import (
	"context"
	"errors"
	"fmt"
	"github.com/viant/datly/exec"
	"github.com/viant/mechanize/data/credentialprotectionscopelegacy"
	"github.com/viant/mechanize/data/credentialprotectionscopelist"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestCredentialProtectionScopeGeneratedImmutableReopen(t *testing.T) {
	ctx, p := privateActor(t)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "login"})
	root := filepath.Join(t.TempDir(), "missing-source")
	storage := t.TempDir()
	b, e := New(Options{SourceRoot: root, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("scope requested execution lease")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("scope dispatched input")
		return integration.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(context.Background())
	_, lockedUser, e := b.bound(ctx, p, 0)
	if e != nil {
		t.Fatal(e)
	}
	lockedUser.mu.Lock()
	bounded, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
	started := time.Now()
	lockErr := b.WithCredentialDeliveryComponents(bounded, p, func(context.Context, CredentialDeliveryComponentInvoker) error {
		t.Fatal("busy user lock admitted cleanup")
		return nil
	})
	cancel()
	lockedUser.mu.Unlock()
	if !errors.Is(lockErr, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatal("cleanup lock ignored request deadline", lockErr)
	}
	prep := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "session", PreparationID: strings.Repeat("a", 64), GrantID: "grant", PurposeHash: data.CredentialDeliveryPurposeHash("login"), Origin: "https://bank.invalid", SelectedRevision: strings.Repeat("c", 64), ProtectionState: "held", Revision: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	scope := data.CredentialProtectionScopeRecord{Namespace: p.Namespace, ClientID: p.ClientID, PreparationID: prep.PreparationID, Origin: prep.Origin, ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, FrameID: 0, DocumentID: "login-document", DocumentGeneration: 1, ChromeStartToken: "123:456", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("d", 64), LoginRouteSHA256: strings.Repeat("e", 64), CreatedAt: prep.CreatedAt}
	e = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		bound, revoke, e := data.WithCredentialPreparationAuthority(held, prep, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		defer revoke()
		if e = b.ReserveCredentialPreparation(bound, p); e != nil {
			return e
		}
		before, e := b.CredentialProtectionScopes(bound, p, prep.Origin)
		if e != nil || len(before) != 1 || before[0].Scope.Exact() || before[0].LegacySource != nil {
			t.Fatal("unbound preparation lost origin barrier", e)
		}

		legacy := data.CredentialDeliveryRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: prep.SessionID, AttemptID: strings.Repeat("f", 64), SelectionID: prep.PreparationID, SelectedRevision: prep.SelectedRevision, GrantID: prep.GrantID, PurposeHash: prep.PurposeHash, Origin: prep.Origin, ProfileChannel: scope.ProfileChannel, BrowserInstance: scope.BrowserInstance, TabID: scope.TabID, DocumentID: scope.DocumentID, DocumentGeneration: 1, BrokerEpoch: scope.BrokerEpoch, ChannelEpoch: scope.ChannelEpoch, ScopeHash: scope.ScopeHash, RendererLeaseID: "lease", RendererLeaseGeneration: 1, ChromeStartToken: scope.ChromeStartToken, NativeHostStartToken: "234:567", DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: prep.CreatedAt, UpdatedAt: prep.CreatedAt}
		legacyCtx, legacyStop, e := data.WithCredentialDeliveryAuthority(held, data.CredentialDeliveryAuthority{Record: legacy}, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		defer legacyStop()
		if e = b.ReserveCredentialDelivery(legacyCtx, p); e != nil {
			return e
		}
		preflight, finish, e := data.WithCredentialPreflightCleanupAuthority(held, prep, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		closed := prep
		closed.ProtectionState = "closed"
		closed.Revision++
		closeCtx, closeStop, e := data.WithCredentialPreparationAuthority(preflight, closed, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		if e = b.CloseCredentialPreparation(closeCtx, p); e == nil {
			t.Fatal("typed preflight cleanup accepted a nonzero generated child snapshot")
		}
		closeStop()
		finish()
		projection, e := b.CredentialProtectionScopes(bound, p, prep.Origin)
		if e != nil || len(projection) != 1 || projection[0].Scope.Exact() || projection[0].LegacySource == nil || projection[0].LegacySource.DocumentID != scope.DocumentID || len(projection[0].Attempts) != 0 {
			t.Fatal("legacy source metadata not derived without history", projection, e)
		}
		for _, bad := range []data.CredentialProtectionScopeRecord{func() data.CredentialProtectionScopeRecord {
			x := scope
			x.Origin = "https://foreign.invalid"
			return x
		}(), func() data.CredentialProtectionScopeRecord { x := scope; x.ClientID = "foreign"; return x }(), func() data.CredentialProtectionScopeRecord {
			x := scope
			x.LoginRouteSHA256 = "PRIVATE_CANARY"
			return x
		}()} {
			if _, _, e = data.WithCredentialProtectionScopeAuthority(bound, bad); e == nil {
				t.Fatal("false source scope sealed")
			}
		}
		sealed, stop, e := data.WithCredentialProtectionScopeAuthority(bound, scope)
		if e != nil {
			return e
		}
		defer stop()
		if e = b.ReserveCredentialProtectionScope(sealed, p); e != nil {
			return e
		}
		if e = b.ReserveCredentialProtectionScope(sealed, p); e == nil {
			t.Fatal("scope replay accepted")
		}
		actual, e := b.CredentialProtectionScopes(bound, p, prep.Origin)
		if e != nil || len(actual) != 1 || actual[0].Scope != scope {
			t.Fatal("generated source projection differs", actual, e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = b.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	reopened := &Builder{options: Options{SourceRoot: root, StorageRoot: storage, MaxUsers: 1}, users: map[string]*userHost{}}
	defer reopened.Close(context.Background())
	actual, e := reopened.CredentialProtectionScopes(ctx, p, prep.Origin)
	if e != nil || len(actual) != 1 || actual[0].Scope != scope {
		t.Fatal("restart lost immutable source", actual, e)
	}
	if blocked, e := reopened.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		t.Fatal("scope publication erased held protection", e)
	}
}

func TestCredentialProtectionProjectionUsesBoundedMetadataQueries(t *testing.T) {
	ctx, p := privateActor(t)
	for _, relevant := range []bool{false, true} {
		calls := 0
		rows := make([]*credentialprotectionscopelist.ProtectionScope, 0, 40)
		legacy := make([]*credentialprotectionscopelegacy.LegacySource, 0, 40)
		origin := "https://bank.invalid"
		for i := 0; i < 40; i++ {
			id := fmt.Sprintf("%064x", i+1)
			rows = append(rows, &credentialprotectionscopelist.ProtectionScope{Namespace: &p.Namespace, ClientId: &p.ClientID, PreparationId: &id, Origin: &origin})
			profile, browser, doc, birth := "profile", "browser", "document", "123:456"
			tab, generation := i+1, 1
			legacy = append(legacy, &credentialprotectionscopelegacy.LegacySource{Namespace: &p.Namespace, ClientId: &p.ClientID, PreparationId: &id, Origin: &origin, ProfileChannel: &profile, BrowserInstance: &browser, TabId: &tab, DocumentId: &doc, DocumentGeneration: &generation, ChromeStartToken: &birth})
		}
		target := "https://different.invalid"
		if relevant {
			target = origin
		}
		started := time.Now()
		result, e := readCredentialProtectionProjection(ctx, p, []string{target}, func(_ context.Context, r exec.ComponentRequest) (any, error) {
			calls++
			switch r.Target.Component.Name {
			case "CredentialProtectionScopeList":
				return &credentialprotectionscopelist.CredentialProtectionScopeListOutput{Data: rows}, nil
			case "CredentialProtectionScopeLegacy":
				return &credentialprotectionscopelegacy.CredentialProtectionScopeLegacyOutput{Data: legacy}, nil
			default:
				t.Fatal("ordinary admission loaded full history", r.Target.Component.Name)
				return nil, nil
			}
		})
		expected := 1
		if relevant {
			expected = 2
		}
		if e != nil || len(result) != 40 || calls != expected {
			t.Fatal("ordinary scope queries scaled with preparations", len(result), calls, e)
		}
		for _, row := range result {
			if (row.LegacySource != nil) != relevant {
				t.Fatal("legacy source projection missing or unnecessary")
			}
		}
		t.Logf("40 protected sources: %d metadata queries in %s", calls, time.Since(started))
	}
}
