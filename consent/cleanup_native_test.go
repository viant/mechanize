package consent_test

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/consent"
	"testing"
)

func suspendedDesktopGrant(t *testing.T, f *fixture) *consent.Grant {
	t.Helper()
	in := input()
	in.Scope = consent.Scope{Kind: "desktop"}
	req, err := f.service.CreateRequest(f.client, "fixture-session", in)
	if err != nil {
		t.Fatal(err)
	}
	g, err := f.service.Decide(f.admin, req.ID, consent.AllowUntilRevoked)
	if err != nil {
		t.Fatal(err)
	}
	active, err := f.service.Authorize(f.client, operation(g))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.ReportDispatchCleanupUnknown(f.client, g.ID); err != nil {
		t.Fatal(err)
	}
	active.Release()
	return g
}
func TestNativeCleanupLeaseLeavesBroadGrantAndAuditSuspended(t *testing.T) {
	f := newFixture(t)
	g := suspendedDesktopGrant(t, f)
	before, _ := json.Marshal(auditRows(t, f, g.RequestID))
	proofs := 0
	options := f.options
	options.RecoverNativeCleanup = func(_ context.Context, c consent.Client, scope consent.Scope) error {
		proofs++
		if c.ID != g.ClientID || scope != (consent.Scope{Kind: "application", BundleID: "com.example.Editor"}) {
			t.Fatal("proof scope widened")
		}
		return nil
	}
	restarted, err := consent.New(options)
	if err != nil {
		t.Fatal(err)
	}
	op := operation(g)
	op.Scope = consent.Scope{Kind: "application", BundleID: "com.example.Editor"}
	found, err := restarted.FindPermanentGrant(f.client, op)
	if err != nil || found == nil || found.RevocationState != consent.CleanupUnknown || proofs != 0 {
		t.Fatal("discovery restored approval", err)
	}
	lease, err := restarted.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	if lease.Context.Err() != nil || proofs != 1 {
		t.Fatal("native lease not proved")
	}
	lease.Release()
	after, _ := json.Marshal(auditRows(t, f, g.RequestID))
	if string(before) != string(after) {
		t.Fatal("native proof changed durable grant/audit")
	}
	for _, scope := range []consent.Scope{{Kind: "origin", Origin: "https://fixture.invalid"}, {Kind: "browser", BundleID: "com.google.Chrome"}, {Kind: "application", BundleID: "com.google.Chrome"}, {Kind: "desktop"}} {
		denied := op
		denied.Scope = scope
		if _, err = restarted.Authorize(f.client, denied); err == nil {
			t.Fatal("browser or desktop authority restored")
		}
	}
	if proofs != 1 {
		t.Fatal("web uncertainty invoked native-only proof")
	}
	foreignOptions := options
	foreignOptions.VerifyClient = func(context.Context) (consent.Client, error) {
		return consent.Client{ID: "foreign", DisplayName: "Foreign", SessionID: "fixture-session", Verification: "verified"}, nil
	}
	foreign, _ := consent.New(foreignOptions)
	if _, err = foreign.Authorize(f.client, op); err == nil {
		t.Fatal("foreign client admitted")
	}
	badSession := op
	badSession.SessionID = "other"
	if _, err = restarted.Authorize(f.client, badSession); err == nil {
		t.Fatal("foreign session admitted")
	}
	if proofs != 1 {
		t.Fatal("foreign authority reached proof")
	}
	// Human revoke still cancels admitted native-only work and persists a barrier.
	lease, err = restarted.Authorize(f.client, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Revoke(f.admin, g.ID); err != nil {
		t.Fatal(err)
	}
	if lease.Context.Err() == nil {
		t.Fatal("human revoke did not cancel native lease")
	}
	lease.Release()
	if _, err = restarted.Authorize(f.client, op); err == nil {
		t.Fatal("human revoke bypassed")
	}
	final, _ := consent.New(options)
	if _, err = final.Authorize(f.client, op); err == nil {
		t.Fatal("restart lost human revoke")
	}
}
func TestNativeCleanupProofCannotOverrideFailureCancellationOrConcurrentHumanStop(t *testing.T) {
	for _, mode := range []string{"failed", "canceled", "humanStop"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			g := suspendedDesktopGrant(t, f)
			options := f.options
			ctx, cancel := context.WithCancel(f.client)
			defer cancel()
			options.RecoverNativeCleanup = func(context.Context, consent.Client, consent.Scope) error {
				switch mode {
				case "failed":
					return errors.New("unreleased input")
				case "canceled":
					cancel()
				case "humanStop":
					_, err := f.service.Revoke(f.admin, g.ID)
					return err
				}
				return nil
			}
			restarted, err := consent.New(options)
			if err != nil {
				t.Fatal(err)
			}
			op := operation(g)
			op.Scope = consent.Scope{Kind: "application", BundleID: "com.example.Editor"}
			if _, err = restarted.Authorize(ctx, op); err == nil {
				t.Fatal("unconfirmed cleanup admitted")
			}
		})
	}
}
