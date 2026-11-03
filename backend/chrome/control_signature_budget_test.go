package chrome

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/script"
)

func TestMutationSignatureBudgetKeepsFreshInputCheck(t *testing.T) {
	for _, failAtInput := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "signatureChangedAfterCommit"}[failAtInput], func(t *testing.T) {
			g, p, ctx, inputs := controlFixtureVersion(t, 2)
			var full, identity atomic.Int32
			var committed atomic.Bool
			original := g.broker.verifyPeer
			g.broker.verifyPeer = func(c context.Context, n *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
				full.Add(1)
				if failAtInput && committed.Load() {
					return nativepeer.ChromeProcessEvidence{}, errors.New("signature changed")
				}
				return original(c, n)
			}
			g.broker.verifyPeerIdentity = func(context.Context, *net.UnixConn, nativepeer.ChromeProcessEvidence) error {
				identity.Add(1)
				return nil
			}
			a, err := g.AdmitControl(ctx, p, modelSurfaceFixture())
			if err != nil {
				t.Fatal(err)
			}
			admissionChecks := full.Load()
			if admissionChecks != 1 {
				t.Fatalf("expected one full admission check, got %d", admissionChecks)
			}
			if _, err = g.PinControlRead(ctx, p, a); err != nil {
				t.Fatal(err)
			}
			if full.Load() != admissionChecks {
				t.Fatal("metadata pin repeated full signature scan")
			}
			plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("save",exact:true).click()`)
			if err != nil {
				t.Fatal(err)
			}
			result, err := g.ExecuteControlBound(ctx, p, plan.Steps[0], nil, a, strings.Repeat("a", 64), func(context.Context, auth.Principal, BoundMutation) (BindingCommit, error) {
				committed.Store(true)
				return BindingCommit{BindingID: strings.Repeat("b", 64), CommitConfirmed: true, ReadbackMatched: true}, nil
			})
			if failAtInput {
				if err == nil || result.DispatchState != "notDispatched" || inputs.Load() != 0 || !committed.Load() {
					t.Fatalf("changed signature reached input: %+v %v inputs=%d", result, err, inputs.Load())
				}
				return
			}
			if err != nil || result.DispatchState != "dispatched" || inputs.Load() != 1 {
				t.Fatalf("mutation failed: %+v %v", result, err)
			}
			if full.Load()-admissionChecks != 1 {
				t.Fatalf("expected one fresh input check, got %d", full.Load()-admissionChecks)
			}
			beforeRetire := full.Load()
			retired, err := g.RetireControl(ctx, p, a)
			if err != nil || !retired {
				t.Fatal("retirement failed", err)
			}
			if full.Load()-beforeRetire != 1 || identity.Load() == 0 {
				t.Fatalf("retirement duplicated signature scans: full=%d identity=%d", full.Load()-beforeRetire, identity.Load())
			}
		})
	}
}
