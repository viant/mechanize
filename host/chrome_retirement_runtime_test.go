package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/backend/chrome"
	"strings"
	"testing"
)

func TestChromeRetirementConfigRequiresSignedEnrollment(t *testing.T) {
	for _, c := range []Config{
		{ChromeRetirement: &ChromeRetirementConfig{BrokerRequirement: "broker pin"}},
		{ChromeRetirement: &ChromeRetirementConfig{BrokerRequirement: "broker pin"}, Chrome: &chrome.Config{FixtureEnrollment: true, ProcessTrust: &nativepeer.ChromeProcessPolicy{}}},
		{ChromeRetirement: &ChromeRetirementConfig{BrokerRequirement: "broker pin"}, Chrome: &chrome.Config{}},
		{ChromeRetirement: &ChromeRetirementConfig{BrokerRequirement: ""}, Chrome: &chrome.Config{ProcessTrust: &nativepeer.ChromeProcessPolicy{}}},
	} {
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "retirement requires signed Chrome enrollment") {
			t.Fatal("unqualified retirement config accepted", err)
		}
	}
}
func TestChromeRetirementRuntimeRequiresEnrollmentAndActor(t *testing.T) {
	h := &Host{}
	if err := h.configureChromeRetirement(Config{}); err != nil || h.chromeRetirementEvidence != nil {
		t.Fatal("optional absence enabled retirement", err)
	}
	if _, err := h.PrepareChromeRetirement(context.Background(), "r", "p", "b"); err == nil {
		t.Fatal("unauthenticated call accepted")
	}
	p, _ := auth.NewPrincipal("fixture", "", "subject", []string{"desktop:control"})
	p.ClientID = "client"
	if _, err := h.PrepareChromeRetirement(auth.WithPrincipal(context.Background(), p), "r", "p", "b"); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatal("unenrolled runtime accepted", err)
	}
}
