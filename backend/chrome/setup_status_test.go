package chrome

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSetupGuidancePreservesRecoveryAndQualificationBoundaries(t *testing.T) {
	ready := BrowserChannelStatus{Connected: true, ProcessQualified: true, ScopeQualified: true, ExecutorQualified: true, InventoryComplete: true, DocumentCount: 1}
	cases := []struct {
		name      string
		available bool
		channels  []BrowserChannelStatus
		state     string
	}{
		{"not-configured", false, nil, "enrollmentRequired"},
		{"no-owned-channel", true, nil, "enrollmentRequired"},
		{"disconnected", true, []BrowserChannelStatus{{}}, "connectionRequired"},
		{"connected-unqualified", true, []BrowserChannelStatus{{Connected: true}}, "qualificationRequired"},
		{"ready", true, []BrowserChannelStatus{ready}, "ready"},
	}
	for _, change := range []func(*BrowserChannelStatus){func(c *BrowserChannelStatus) { c.FixtureOnly = true }, func(c *BrowserChannelStatus) { c.ProcessQualified = false }, func(c *BrowserChannelStatus) { c.ScopeQualified = false }, func(c *BrowserChannelStatus) { c.ExecutorQualified = false }, func(c *BrowserChannelStatus) { c.InventoryComplete = false }, func(c *BrowserChannelStatus) { c.AttentionCode = "secret-canary" }} {
		c := ready
		change(&c)
		cases = append(cases, struct {
			name      string
			available bool
			channels  []BrowserChannelStatus
			state     string
		}{"qualification", true, []BrowserChannelStatus{c}, "qualificationRequired"})
	}
	noPage := ready
	noPage.DocumentCount = 0
	unknown := ready
	unknown.UnknownCount = 1
	pending := ready
	pending.PendingCount = 1
	cases = append(cases,
		struct {
			name      string
			available bool
			channels  []BrowserChannelStatus
			state     string
		}{"no-document", true, []BrowserChannelStatus{noPage}, "pageRequired"},
		struct {
			name      string
			available bool
			channels  []BrowserChannelStatus
			state     string
		}{"ready-with-unknown-channel", true, []BrowserChannelStatus{ready, unknown}, "recoveryRequired"},
		struct {
			name      string
			available bool
			channels  []BrowserChannelStatus
			state     string
		}{"pending-with-unknown", true, []BrowserChannelStatus{pending, unknown}, "recoveryRequired"},
		struct {
			name      string
			available bool
			channels  []BrowserChannelStatus
			state     string
		}{"pending", true, []BrowserChannelStatus{ready, pending}, "operationPending"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := (BrowserStatus{Available: tc.available, Channels: tc.channels}).SetupStatus()
			if got.State != tc.state || got.NextAction == "" {
				t.Fatalf("wrong setup state: %+v", got)
			}
			raw, _ := json.Marshal(got)
			if strings.Contains(string(raw), "secret-canary") {
				t.Fatal("attention value leaked into setup guidance")
			}
		})
	}
}

func TestSetupGuidanceExplainsConnectionSetupFailures(t *testing.T) {
	for _, tc := range []struct{ code, state string }{
		{"websiteScopeMismatch", "websiteScopeMismatch"}, {"lifecycleInhibited", "recoveryRequired"},
	} {
		channel := BrowserChannelStatus{Connected: true, AttentionCode: tc.code}
		status := BrowserStatus{Available: true, Channels: []BrowserChannelStatus{channel}}
		got := status.SetupStatus()
		if got.State != tc.state {
			t.Fatalf("%s: %+v", tc.code, got)
		}
		status.Channels[0].PendingCount = 1
		if got := status.SetupStatus(); got.State != "operationPending" {
			t.Fatalf("pending operation lost precedence: %+v", got)
		}
		status.Channels[0].UnknownCount = 1
		if got := status.SetupStatus(); got.State != "recoveryRequired" || !strings.Contains(got.NextAction, "unknown effects") {
			t.Fatalf("unknown effect lost precedence: %+v", got)
		}
	}
}

func TestVisibilityUnknownSetupRetainsOutcomeWithoutClaimingDOMBlocked(t *testing.T) {
	c := BrowserChannelStatus{Connected: true, ProcessQualified: true, ScopeQualified: true, ExecutorQualified: true, InventoryComplete: true, DocumentCount: 1, UnknownCount: 1, VisibilityUnknownCount: 1}
	s := BrowserStatus{Available: true, Channels: []BrowserChannelStatus{c}}
	if r := s.SetupStatus(); r.State != "ready" || !strings.Contains(r.NextAction, "UNKNOWN") {
		t.Fatal(r)
	}
	s.Channels[0].UnknownCount = 2
	if s.SetupStatus().State != "recoveryRequired" {
		t.Fatal("mixed uncertainty exempted")
	}
	s.Channels[0] = c
	s.Channels[0].ProcessQualified = false
	if s.SetupStatus().State != "recoveryRequired" {
		t.Fatal("unqualified classification exposed")
	}
}
