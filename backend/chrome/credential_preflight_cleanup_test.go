package chrome

import (
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
)

func TestPreflightIdleNeverRetiresActiveOrUnknownAuthority(t *testing.T) {
	for _, mode := range []string{"idle", "disconnected", "inspection", "input", "flow", "privacy", "unknown", "control", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, _ := setupFixture(t)
			ctx := auth.WithConsentBinding(base, auth.ConsentBinding{SessionID: "new-owned", GrantID: "current", Purpose: "login"})
			g.broker.mu.Lock()
			switch mode {
			case "disconnected":
				c.conn = nil
			case "inspection":
				c.privateInspection = &credentialAdmissionPending{}
			case "input":
				c.privateCredential = &credentialDeliveryPending{}
			case "flow":
				c.privateFlow = &credentialFlow{}
			case "privacy":
				c.privacy = &credentialPrivacyState{}
			case "unknown":
				c.unknown["original"] = true
			}
			g.broker.mu.Unlock()
			if mode == "control" {
				g.control = &ControlAuthority{}
			}
			if mode == "foreign" {
				p.ClientID = "other"
			}
			e := g.RetireCredentialPreflight(ctx, p, strings.Repeat("b", 64), c.grant.Origins[0])
			if (e == nil) != (mode == "idle" || mode == "disconnected") {
				t.Fatal(mode, e)
			}
			if mode == "unknown" && !c.unknown["original"] {
				t.Fatal("unknown history cleared")
			}
			if mode == "control" && g.control == nil {
				t.Fatal("control retired")
			}
		})
	}
}
