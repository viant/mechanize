package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	native "github.com/viant/mechanize/backend/darwin"
	"testing"
)

func TestNativePolicyReusesOnlyCurrentExactAdmission(t *testing.T) {
	for _, mode := range []string{"same", "normalPolicy", "wrongEpoch", "foreignGateway", "changedClient", "inhibited", "enrollmentRemoved", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			h, f := hostControlFixture(t)
			a := f.admit(t)
			checks, qualify := f.executableChecks, f.qualifications
			ctx, p := f.ctx, f.principal
			switch mode {
			case "wrongEpoch":
				a.Epoch++
			case "foreignGateway":
				a.Gateway = &native.Gateway{}
			case "changedClient":
				actual := p
				actual.ClientID = "other-client"
				ctx = auth.WithPrincipal(ctx, actual)
			case "inhibited":
				f.manager.held.inhibited = true
			case "enrollmentRemoved":
				f.enrolled = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var err error
			if mode == "normalPolicy" {
				_, err = h.Policy(ctx, p)
			} else {
				_, err = h.policy(ctx, p, &a)
			}
			if mode == "same" {
				if err != nil || f.executableChecks != checks || f.qualifications != qualify {
					t.Fatalf("same-operation policy repeated qualification checks=%d readiness=%d err=%v", f.executableChecks-checks, f.qualifications-qualify, err)
				}
			}
			if mode == "normalPolicy" || mode == "wrongEpoch" || mode == "foreignGateway" || mode == "changedClient" {
				if f.executableChecks != checks+1 || f.qualifications != qualify+1 {
					t.Fatalf("other/unbound policy borrowed prior admission checks=%d readiness=%d", f.executableChecks-checks, f.qualifications-qualify)
				}
			}
			if mode == "inhibited" || mode == "enrollmentRemoved" || mode == "cancelled" {
				if f.manager.admissionCurrent(ctx, p, a) {
					t.Fatal("invalid admission retained")
				}
			}
		})
	}
}
func TestNativePolicyReuseDoesNotBypassFreshInputProcessPermissionOrReadiness(t *testing.T) {
	for _, mode := range []string{"processReplaced", "signatureIdentityDenied", "permissionWithdrawn", "sessionLocked", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			h, f := hostControlFixture(t)
			a := f.admit(t)
			if _, err := h.policy(f.ctx, f.principal, &a); err != nil {
				t.Fatal(err)
			}
			before := f.calls
			ctx := f.ctx
			switch mode {
			case "processReplaced":
				f.identity.StartToken = "replacement"
			case "signatureIdentityDenied":
				f.identityErr = ErrNativeControlUnqualified
			case "permissionWithdrawn":
				f.enrolled = nil
			case "sessionLocked":
				f.ready.Unlocked = false
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			_, err := f.caller().Call(ctx, mutation(f))
			if err == nil || f.calls != before {
				t.Fatalf("changed current input authority dispatched calls=%d err=%v", f.calls-before, err)
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation classification lost: %v", err)
			}
		})
	}
}
