package durable

import (
	"context"
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
	"github.com/viant/mechanize/internal/datlytest"
	"github.com/viant/mechanize/model"
)

func TestCredentialCleanupPreservesOutcomesAndClosesUnderCurrentConsent(t *testing.T) {
	testCredentialProtectionCleanup(t, false)
}
func TestCredentialRetirementKeepsUnknownOutcomeAndAudit(t *testing.T) {
	testCredentialProtectionCleanup(t, true)
}
func testCredentialProtectionCleanup(t *testing.T, retireUnknown bool) {
	ctx, p := privateActor(t)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "old-session", GrantID: "old-grant", Purpose: "login"})
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	storage := t.TempDir()
	b, e := New(Options{SourceRoot: root, StorageRoot: storage, LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("cleanup asked for input fence")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("cleanup dispatched input")
		return integration.StepResult{}, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close(context.Background())
	allow := func(context.Context) error { return nil }
	now := time.Now().UTC().Format(time.RFC3339Nano)
	prep := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "old-session", GrantID: "old-grant", PreparationID: strings.Repeat("a", 64), PurposeHash: data.CredentialDeliveryPurposeHash("login"), Origin: "https://fixture.invalid", SelectedRevision: strings.Repeat("b", 64), ProtectionState: "held", Revision: 1, CreatedAt: now}
	records := []data.CredentialDeliveryRecord{}
	states := []string{"dispatched", "notDispatched"}
	if retireUnknown {
		states = append(states, "unknown")
	}
	e = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		bound, revoke, e := data.WithCredentialPreparationAuthority(held, prep, allow)
		if e != nil {
			return e
		}
		defer revoke()
		if e = b.ReserveCredentialPreparation(bound, p); e != nil {
			return e
		}
		for i, state := range states {
			r := data.CredentialDeliveryRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: prep.SessionID, GrantID: prep.GrantID, SelectionID: prep.PreparationID, SelectedRevision: prep.SelectedRevision, PurposeHash: prep.PurposeHash, Origin: prep.Origin, AttemptID: strings.Repeat(string(rune('c'+i)), 64), ProfileChannel: "profile", BrowserInstance: "browser", DocumentID: "document", DocumentGeneration: 1, TabID: 7, BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: strings.Repeat("e", 64), RendererLeaseID: "lease", RendererLeaseGeneration: 1, ChromeStartToken: "123:456", NativeHostStartToken: "234:567", DispatchState: "unknown", ProtectionState: "held", Revision: 1, CreatedAt: now, UpdatedAt: now}
			c, stop, e := data.WithCredentialDeliveryAuthority(held, data.CredentialDeliveryAuthority{Record: r}, allow)
			if e != nil {
				return e
			}
			e = b.ReserveCredentialDelivery(c, p)
			stop()
			if e != nil {
				return e
			}
			next := r
			next.DispatchState = state
			next.Revision++
			next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			c, stop, e = data.WithCredentialDeliveryAuthority(held, data.CredentialDeliveryAuthority{Record: next, Before: &r}, allow)
			if e != nil {
				return e
			}
			e = b.FinishCredentialDelivery(c, p)
			stop()
			if e != nil {
				return e
			}
			records = append(records, next)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	current := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "recovery-session", GrantID: "recovery-grant", Purpose: "retire original browser"})
	allowed := &atomic.Bool{}
	allowed.Store(true)
	guard := func(context.Context) error {
		if !allowed.Load() {
			return errors.New("retirement evidence revoked")
		}
		return nil
	}
	e = b.WithCredentialDeliveryComponents(current, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		actual, children, e := b.LoadCredentialRecovery(held, p, prep.PreparationID)
		if e != nil || actual != prep || len(children) != len(states) {
			t.Fatal("metadata recovery failed", e)
		}
		if _, _, e = data.WithCredentialCleanupAuthority(held, actual, children, nil); e == nil {
			t.Fatal("missing retirement evidence admitted")
		}
		unknown := append([]data.CredentialDeliveryRecord(nil), children...)
		unknown[0].DispatchState = "unknown"
		if _, _, e = data.WithCredentialCleanupAuthority(held, actual, unknown, guard); e == nil {
			t.Fatal("unknown input allowed cleanup")
		}
		clean, stop, e := data.WithCredentialCleanupAuthority(held, actual, children, guard)
		if retireUnknown {
			if _, _, err := data.WithCredentialRetirementAuthority(held, actual, children, "foreign-birth", guard); err == nil {
				t.Fatal("foreign retirement birth accepted")
			}
			allowed.Store(false)
			if _, _, err := data.WithCredentialRetirementAuthority(held, actual, children, "123:456", guard); err == nil {
				t.Fatal("live/unproven retirement accepted")
			}
			allowed.Store(true)
			clean, stop, e = data.WithCredentialRetirementAuthority(held, actual, children, "123:456", guard)
		}
		if e != nil {
			return e
		}
		defer stop()
		closed := prep
		closed.ProtectionState = "closed"
		closed.Revision++
		pre, release, e := data.WithCredentialPreparationAuthority(clean, closed, guard)
		if e != nil {
			return e
		}
		defer release()
		if e = b.CloseCredentialPreparation(pre, p); e == nil {
			t.Fatal("parent closed before children")
		}
		for _, old := range children {
			next := old
			next.ProtectionState = "closed"
			if old.DispatchState == "unknown" {
				next.ProtectionState = "retired"
			}
			next.Revision++
			next.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			changed := next
			changed.DispatchState = "notDispatched"
			if old.DispatchState == "notDispatched" {
				changed.DispatchState = "dispatched"
			}
			if _, _, e = data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Record: changed, Before: &old}, guard); e == nil {
				t.Fatal("cleanup rewrote dispatch knowledge")
			}
			c, revoke, e := data.WithCredentialDeliveryAuthority(clean, data.CredentialDeliveryAuthority{Record: next, Before: &old}, guard)
			if e != nil {
				return e
			}
			e = b.FinishCredentialDelivery(c, p)
			revoke()
			if e != nil {
				return e
			}
		}
		if e = b.CloseCredentialPreparation(pre, p); e != nil {
			return e
		}
		actual, children, e = b.LoadCredentialRecovery(held, p, prep.PreparationID)
		if e != nil || actual != closed || len(children) != len(states) {
			t.Fatal("closed history lost", e)
		}
		for _, v := range children {
			wantProtection := "closed"
			if v.DispatchState == "unknown" {
				wantProtection = "retired"
			}
			var original data.CredentialDeliveryRecord
			for _, record := range records {
				if record.AttemptID == v.AttemptID {
					original = record
				}
			}
			if v.ProtectionState != wantProtection || v.DispatchState != original.DispatchState || v.ChromeStartToken != original.ChromeStartToken || v.Revision != 3 {
				t.Fatal("child closure missing")
			}
		}
		if blocked, e := b.CredentialDeliveryBlocked(held, p); e != nil || blocked {
			t.Fatal("confirmed closure still blocking", e)
		}
		allowed.Store(false)
		if _, e = b.ReadCredentialPreparation(pre, p); e == nil {
			t.Fatal("revoked evidence remained usable")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// Independent scoped generated reader proves append-only audit counts.
	scoped, e := data.WithScope(ctx, data.Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := data.Provision(scoped, storage, data.Scope{Namespace: p.Namespace})
	if e != nil {
		t.Fatal(e)
	}
	observer, e := datlytest.Open(scoped, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer observer.Shutdown(context.Background())
	counts, e := datlytest.CountAudits(scoped, observer, p.Namespace)
	if e != nil || counts.Deliveries != 3*len(states) || counts.Preparations != 2 {
		t.Fatal("append-only audit counts changed", counts, e)
	}
	// A fresh flow can coexist with immutable closed history.
	prep.PreparationID = strings.Repeat("f", 64)
	e = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		c, stop, e := data.WithCredentialPreparationAuthority(held, prep, allow)
		if e != nil {
			return e
		}
		defer stop()
		return b.ReserveCredentialPreparation(c, p)
	})
	if e != nil {
		t.Fatal("new preparation blocked by closed history", e)
	}
}

func TestCredentialCleanupClosesUnfilledPreparationWithRetirementProof(t *testing.T) {
	ctx, p := privateActor(t)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "original", GrantID: "grant", Purpose: "login"})
	_, file, _, _ := runtime.Caller(0)
	b, err := New(Options{SourceRoot: filepath.Clean(filepath.Join(filepath.Dir(file), "../..")), StorageRoot: t.TempDir(), LeaseEpoch: func(context.Context, auth.Principal) (int, error) {
		t.Fatal("cleanup requested input lease")
		return 0, nil
	}}, func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
		t.Fatal("cleanup dispatched input")
		return integration.StepResult{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close(context.Background())
	guard := func(context.Context) error { return nil }
	prep := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, SessionID: "original", GrantID: "grant", PreparationID: strings.Repeat("a", 64), PurposeHash: data.CredentialDeliveryPurposeHash("login"), Origin: "https://fixture.invalid", SelectedRevision: strings.Repeat("b", 64), ProtectionState: "held", Revision: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	err = b.WithCredentialDeliveryComponents(ctx, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		bound, revoke, e := data.WithCredentialPreparationAuthority(held, prep, guard)
		if e != nil {
			return e
		}
		defer revoke()
		return b.ReserveCredentialPreparation(bound, p)
	})
	if err != nil {
		t.Fatal(err)
	}
	current := auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "recovery", GrantID: "current", Purpose: "retire original browser"})
	err = b.WithCredentialDeliveryComponents(current, p, func(held context.Context, _ CredentialDeliveryComponentInvoker) error {
		actual, children, e := b.LoadCredentialRecovery(held, p, prep.PreparationID)
		if e != nil || actual != prep || len(children) != 0 {
			t.Fatal("complete empty snapshot unavailable", e)
		}
		if _, _, e = data.WithCredentialCleanupAuthority(held, actual, children, nil); e == nil {
			t.Fatal("missing retirement proof accepted")
		}
		clean, stop, e := data.WithCredentialCleanupAuthority(held, actual, children, guard)
		if e != nil {
			return e
		}
		defer stop()
		actual.ProtectionState = "closed"
		actual.Revision++
		bound, revoke, e := data.WithCredentialPreparationAuthority(clean, actual, guard)
		if e != nil {
			return e
		}
		defer revoke()
		if e = b.CloseCredentialPreparation(bound, p); e != nil {
			return e
		}
		if blocked, e := b.CredentialDeliveryBlocked(bound, p); e != nil || blocked {
			t.Fatal("unfilled preparation remains blocked", e)
		}
		got, children, e := b.LoadCredentialRecovery(bound, p, prep.PreparationID)
		if e != nil || got != actual || len(children) != 0 {
			t.Fatal("original preparation audit not preserved", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
