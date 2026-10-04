package host

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestDesktopRecordingConsentScopeRejectsMixedTargets(t *testing.T) {
	scope, err := ConsentScope(model.Surface{Kind: "desktop"})
	if err != nil || scope.Kind != "desktop" {
		t.Fatalf("desktop scope: %+v, %v", scope, err)
	}
	for _, surface := range []model.Surface{
		{Kind: "desktop", BundleID: "com.apple.finder"},
		{Kind: "desktop", Origin: "https://example.com"},
		{Kind: "desktop", Title: "Document"},
		{Kind: "desktop", TabID: "7"},
		{Kind: "desktop", ProcessID: 10, ProcessStartToken: "123:456"},
	} {
		if _, err := ConsentScope(surface); err == nil {
			t.Fatalf("mixed target broadened to desktop: %+v", surface)
		}
	}
}

func TestConsentProcessIdentityNeverWidensTarget(t *testing.T) {
	for _, surface := range []model.Surface{
		{Kind: "web", Origin: "https://example.com", ProcessID: 10, ProcessStartToken: "123:456"},
		{Kind: "native", BundleID: "com.apple.calculator", ProcessID: 10},
		{Kind: "native", BundleID: "com.apple.calculator", Origin: "https://example.com"},
		{Kind: "web", Origin: "https://example.com", BundleID: "com.apple.calculator"},
	} {
		if _, err := ConsentScope(surface); err == nil {
			t.Fatalf("mixed target accepted: %+v", surface)
		}
	}
	scope, err := ConsentScope(model.Surface{Kind: "native", BundleID: "com.apple.calculator", ProcessID: 10, ProcessStartToken: "123:456"})
	if err != nil || scope.Kind != "application" || scope.BundleID != "com.apple.calculator" {
		t.Fatalf("narrow native target: %+v, %v", scope, err)
	}
}
