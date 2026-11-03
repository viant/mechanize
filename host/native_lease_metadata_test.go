package host

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
)

func TestNativeLeaseMetadataDoesNotDuplicateDispatchQualification(t *testing.T) {
	f := newControlFixture(t)
	f.admit(t)
	before := f.qualifications
	lease, err := f.manager.lease(f.ctx, f.principal, f.manager.held)
	if err != nil || lease.ID == "" || lease.Generation == 0 || f.qualifications != before || f.calls != 0 {
		t.Fatalf("metadata performed helper work: %+v %v", lease, err)
	}
	request := mutation(f)
	request.Lease = &lease
	if _, err = f.caller().Call(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	if f.qualifications != before+1 || f.calls != 1 {
		t.Fatal("actual dispatch did not freshly qualify exactly once")
	}
}

func TestNativeLeaseMetadataCannotAuthorizeUnqualifiedHelperRequests(t *testing.T) {
	for _, method := range []string{"lease.install", "elements.press", "apps.list"} {
		for _, gate := range []string{"graphical", "accessibility", "event-post", "watchdog", "locked"} {
			t.Run(method+"/"+gate, func(t *testing.T) {
				f := newControlFixture(t)
				f.admit(t)
				switch gate {
				case "graphical":
					f.ready.ActiveGraphicalSession = false
				case "accessibility":
					f.ready.Accessibility = false
				case "event-post":
					f.ready.EventPost = false
				case "watchdog":
					f.ready.WatchdogLive = false
				case "locked":
					f.ready.Unlocked = false
				}
				before := f.qualifications
				lease, err := f.manager.lease(f.ctx, f.principal, f.manager.held)
				if err != nil || f.qualifications != before {
					t.Fatal("metadata became readiness authority", err)
				}
				r := mutation(f)
				r.Method = method
				r.Lease = &lease
				if method == "lease.install" {
					r.Params, _ = json.Marshal(lease)
					r.Lease = nil
				}
				if _, err = f.caller().Call(f.ctx, r); !errors.Is(err, ErrNativeControlUnqualified) {
					t.Fatal("unqualified request accepted", err)
				}
				if f.calls != 0 || f.qualifications != before+1 {
					t.Fatal("readiness was cached or helper invoked")
				}
			})
		}
	}
}

func TestNativeLeaseMetadataRetainsIdentityScopeAndRevocationGates(t *testing.T) {
	for _, mode := range []string{"dead", "replaced", "inhibited", "epoch", "enrollment", "other-owner", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newControlFixture(t)
			f.admit(t)
			held := f.manager.held
			ctx := f.ctx
			switch mode {
			case "dead":
				f.alive = false
			case "replaced":
				f.identity.StartToken = "replacement"
			case "inhibited":
				held.inhibited = true
			case "epoch":
				held.lease.Generation++
			case "enrollment":
				f.enrolled = nil
			case "other-owner":
				other, _ := auth.NewPrincipal("issuer", "tenant", "other", []string{"desktop:control"})
				ctx = auth.WithPrincipal(ctx, other)
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			lease, err := f.manager.lease(ctx, f.principal, held)
			if err == nil || lease != (native.Lease{}) || f.calls != 0 {
				t.Fatal("invalid metadata authority escaped", mode, err)
			}
		})
	}
}
