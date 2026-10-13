package chrome

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/data"
	datahost "github.com/viant/mechanize/data/host"
)

// Seed an existing permanent fixture consent before worker reconnect. Recovery
// uses the real linked Datly CAS guarded by the real browser reconnect seal.
// Native physical cleanup remains a separately tested Host prerequisite.
func historicalConsentRecoveryFixture(t *testing.T, f *reconnectDatlyFixture, g *Gateway) func() error {
	t.Helper()
	ctx, err := data.WithScope(f.ctx, data.Scope{Namespace: f.p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	server, err := datahost.Open(ctx, filepath.Join(t.TempDir(), "absent-source"), f.storage, data.Scope{Namespace: f.p.Namespace})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Shutdown(context.Background()) })
	opened, err := f.runtime.Open(ctx, "existing cleanup consent")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.runtime.Close(ctx, opened.SessionID) })
	client := consent.Client{ID: f.p.ClientID, DisplayName: "Fixture", SessionID: opened.SessionID, Verification: "verified"}
	options := consent.Options{Namespace: f.p.Namespace, Invoke: server.InvokeComponent, VerifyClient: func(context.Context) (consent.Client, error) { return client, nil }, VerifyActor: func(context.Context) (consent.Actor, error) {
		return consent.Actor{ID: "fixture-human", Human: true, Admin: true}, nil
	}, ResolveClient: func(context.Context, string, string) (consent.Client, error) { return client, nil }, Policy: func(context.Context, consent.Client, consent.Scope, []consent.Mode, int) error { return nil }, WithCleanupProof: func(c context.Context, _ consent.Client, _ consent.Scope, commit func(context.Context) error) error {
		return g.WithConsentReconnectProof(c, f.p, func() error { return commit(c) })
	}}
	service, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	req, err := service.CreateRequest(ctx, opened.SessionID, consent.RequestInput{Scope: consent.Scope{Kind: "origin", Origin: "https://fixture.example.test"}, Modes: []consent.Mode{consent.Control}, Purpose: "fixture action", DurationSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.Decide(ctx, req.ID, consent.AllowUntilRevoked)
	if err != nil {
		t.Fatal(err)
	}
	op := consent.Operation{GrantID: grant.ID, SessionID: opened.SessionID, Scope: grant.Scope, Mode: consent.Control, Purpose: grant.Purpose}
	lease, err := service.Authorize(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.ReportDispatchCleanupUnknown(ctx, grant.ID); err != nil {
		lease.Release()
		t.Fatal(err)
	}
	lease.Release()
	// The prior broker/service is gone. Preserve durable cleanup history while
	// rebuilding only the new service registry, as an installed restart does.
	service, err = consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	return func() error {
		if err := service.RecoverDispatchCleanup(ctx, grant.ID); err != nil {
			return err
		}
		retained, err := service.FindPermanentGrant(ctx, op)
		if err != nil {
			return err
		}
		if retained == nil || retained.ID != grant.ID || retained.Scope != grant.Scope || retained.Purpose != grant.Purpose {
			return fmt.Errorf("original consent changed during cleanup")
		}
		lease, err := service.Authorize(ctx, op)
		if err != nil {
			return err
		}
		lease.Release()
		return nil
	}
}
