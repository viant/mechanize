package main

import (
	"github.com/viant/mechanize/backend/containerbrowser"
	"github.com/viant/mechanize/script"
	"strings"
	"testing"
)

func TestConfiguredWebsiteAccess(t *testing.T) {
	for _, tc := range []struct {
		name, config, origin string
		permitted            bool
	}{
		{"default", `{}`, "https://other.example", true},
		{"explicit all", `{"allowAllWeb":true}`, "https://other.example", true},
		{"explicit deny", `{"allowAllWeb":false}`, "https://other.example", false},
		{"allowlisted", `{"allowAllWeb":false,"allowedOrigins":["https://allowed.example"]}`, "https://allowed.example", true},
		{"outside allowlist", `{"allowAllWeb":false,"allowedOrigins":["https://allowed.example"]}`, "https://other.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := decodeConfig(strings.NewReader(tc.config))
			if err != nil {
				t.Fatal(err)
			}
			policy := script.Policy{AllowAllWeb: c.AllowAllWeb, AllowMutation: true, AllowedSurfaces: map[string]bool{}, Capabilities: containerbrowser.BrowserCapabilities()}
			for _, origin := range c.AllowedOrigins {
				policy.AllowedSurfaces[origin] = true
			}
			plan, err := script.Compile(`web.tab(origin: "` + tc.origin + `").openOrigin()`)
			if err != nil {
				t.Fatal(err)
			}
			err = (script.Validator{}).CheckPolicy(plan, policy)
			if (err == nil) != tc.permitted {
				t.Fatalf("permitted=%v error=%v", tc.permitted, err)
			}
		})
	}
}
