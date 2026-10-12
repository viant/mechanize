package host

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/engine/durable"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func TestPrivateChromeQuitRemainsNarrowAndRequiresConsent(t *testing.T) {
	step := model.Step{ID: "quit", TimeoutMs: 1000, Action: "app.quit", Target: model.Selector{Surface: model.Surface{Kind: "native", BundleID: "com.google.Chrome", ProcessID: 123, ProcessStartToken: "123:456"}, Cardinality: "one"}, Effect: model.Effect{Class: model.ExternalNonIdempotent, BusinessKey: map[string]model.Value{"purpose": {Kind: model.StringValue, String: "retire-private-browser"}}}}
	if !privateChromeQuit(step) {
		t.Fatal("exact typed quit refused")
	}
	h := &Host{durable: &durable.Builder{}}
	lease, err := h.authorizeNativeControlStep(context.Background(), auth.Principal{}, step)
	if lease != nil || err == nil || errors.Is(err, vault.ErrUnavailable) {
		t.Fatal("quit bypassed consent or entered ordinary exposure")
	}
	for _, mode := range []string{"activate", "capture", "otherApp", "noPID", "noBirth", "arguments", "locator"} {
		t.Run(mode, func(t *testing.T) {
			s := step
			switch mode {
			case "activate":
				s.Action = "app.activate"
			case "capture":
				s.Action = "element.read"
			case "otherApp":
				s.Target.Surface.BundleID = "com.fixture.app"
			case "noPID":
				s.Target.Surface.ProcessID = 0
			case "noBirth":
				s.Target.Surface.ProcessStartToken = ""
			case "arguments":
				s.Arguments = map[string]model.Value{"text": {Kind: model.StringValue, String: "PRIVATE-CANARY"}}
			case "locator":
				s.Target.Locator = &model.Locator{Strategy: "id", Value: model.Value{Kind: model.StringValue, String: "private"}}
			}
			if privateChromeQuit(s) {
				t.Fatal("non-retirement action admitted")
			}
			// A non-retirement action follows ordinary native ownership and consent
			// checks. Private browser delivery is not a desktop-wide prohibition.
			lease, err := h.authorizeNativeControlStep(context.Background(), auth.Principal{}, s)
			if lease != nil || err == nil || errors.Is(err, vault.ErrUnavailable) {
				t.Fatal("ordinary native ownership or consent bypassed")
			}
		})
	}
}
