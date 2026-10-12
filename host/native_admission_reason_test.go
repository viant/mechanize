package host

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/session"
)

func TestNativeAdmissionReasonsAreClosedWithoutBroadeningCapabilities(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{{ErrNativeControlCleanupUnknown, "nativeCleanupUnknown"}, {session.ErrNoLease, "nativeLeaseUnavailable"}, {context.DeadlineExceeded, "nativeAdmissionDeadline"}, {context.Canceled, "nativeAdmissionCancelled"}, {auth.ErrUnauthorized, "nativeAdmissionUnauthorized"}, {errors.New("PRIVATE_CANARY path=/private/key"), "nativeControlUnqualified"}} {
		if got := nativeControlAdmissionReason(tc.err); got != tc.reason || strings.Contains(got, "PRIVATE") {
			t.Fatal("admission reason unbounded", got)
		}
	}
	h, f := hostControlFixture(t)
	f.identityErr = session.ErrNoLease
	policy, e := h.Policy(f.ctx, f.principal)
	if e != nil {
		t.Fatal(e)
	}
	if policy.Capabilities["native:appActivation"] || policy.CapabilityReasons["native:appActivation"] != "nativeLeaseUnavailable" || f.calls != 0 {
		t.Fatal("failure reason changed authority", policy.CapabilityReasons)
	}
}
