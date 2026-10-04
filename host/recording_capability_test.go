package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	recording "github.com/viant/mechanize/engine/recording"
	"strings"
	"testing"
)

func TestRecordingCapabilityDistinguishesEnrollmentFromWiring(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "employee", []string{"desktop:control"})
	p.ClientID = "client"
	ctx := auth.WithPrincipal(context.Background(), p)
	for _, tc := range []struct {
		name           string
		user           User
		wired, enabled bool
		reason         string
	}{
		{"operator disabled", User{DesktopAccess: true}, true, false, "operator enrollment"},
		{"desktop scope missing", User{RecordingAllowed: true}, true, false, "desktop scope"},
		{"transport missing", User{DesktopAccess: true, RecordingAllowed: true}, false, false, "not configured"},
		{"configured still requires consent", User{DesktopAccess: true, RecordingAllowed: true}, true, true, "scoped consent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{users: map[string]User{p.Namespace: tc.user}}
			if tc.wired {
				h.nativeRecording = &NativeRecordingManager{}
				h.recording = &recording.Service{}
			}
			policy, err := h.Policy(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			if policy.Capabilities["native:recordingTransport"] != tc.enabled || !strings.Contains(policy.CapabilityReasons["native:recordingTransport"], tc.reason) {
				t.Fatal("capability reason mismatch", policy.CapabilityReasons)
			}
			if policy.Capabilities["web:recordingTransport"] {
				t.Fatal("missing Chrome advertised")
			}
		})
	}
}
