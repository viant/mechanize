package durable

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	integration "github.com/viant/mechanize/integration/endly"
	"github.com/viant/mechanize/model"
)

func TestCredentialPreparationSurvivesUnpinnedFailureAndRestart(t *testing.T) {
	ctx, p := privateActor(t)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "login"})
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	b, e := New(Options{SourceRoot: root, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("preparation requested nonexistent document lease")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("preparation dispatched input")
		return integration.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(context.Background())
	preparation := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "session", PreparationID: strings.Repeat("a", 64), GrantID: "grant", PurposeHash: data.CredentialDeliveryPurposeHash("login"), Origin: "https://bank.invalid", SelectedRevision: strings.Repeat("c", 64), ProtectionState: "held", Revision: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(preparation)
	for _, forbidden := range []string{"document", "lease", "account", "reference", "password", "username"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatal("pre-admission record included unavailable or secret fields")
		}
	}
	allowed := &atomic.Bool{}
	allowed.Store(true)
	e = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		if _, _, e := data.WithCredentialPreparationAuthority(held, preparation, nil); e == nil {
			t.Fatal("missing guard accepted")
		}
		other := p
		other.ClientID = "foreign"
		if _, _, e := data.WithCredentialPreparationAuthority(auth.WithPrincipal(held, other), preparation, func(context.Context) error { return nil }); e == nil {
			t.Fatal("foreign actor accepted")
		}
		bound, revoke, e := data.WithCredentialPreparationAuthority(held, preparation, func(context.Context) error {
			if !allowed.Load() {
				return errors.New("guard revoked")
			}
			return nil
		})
		if e != nil {
			return e
		}
		defer revoke()
		if e = b.ReserveCredentialPreparation(bound, p); e != nil {
			return e
		}
		actual, e := b.ReadCredentialPreparation(bound, p)
		if e != nil || actual != preparation {
			t.Fatal("preparation readback differs", e)
		}
		if blocked, e := b.CredentialDeliveryBlocked(bound, p); e != nil || !blocked {
			t.Fatal("unpinned reservation not blocking exposure", e)
		}
		if e = b.ReserveCredentialPreparation(bound, p); e == nil {
			t.Fatal("preparation replay accepted")
		}
		different := preparation
		different.PreparationID = strings.Repeat("d", 64)
		second, stop, e := data.WithCredentialPreparationAuthority(held, different, func(context.Context) error { return nil })
		if e != nil {
			return e
		}
		defer stop()
		if e = b.ReserveCredentialPreparation(second, p); e == nil {
			t.Fatal("unrelated namespace preparation admitted")
		}
		allowed.Store(false)
		if _, e = b.ReadCredentialPreparation(bound, p); e == nil {
			t.Fatal("revoked real guard reused")
		}
		allowed.Store(true)
		revoke()
		if _, e = b.ReadCredentialPreparation(bound, p); e == nil {
			t.Fatal("revoked sealed authority reused")
		}
		// Simulate failed Pin: no child010 row and no document/renderer authority was
		// created. The preparation alone must survive this callback and restart.
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
	if blocked, e := reopened.CredentialDeliveryBlocked(ctx, p); e != nil || !blocked {
		t.Fatal("restart erased failed unpinned preparation", e)
	}
}
