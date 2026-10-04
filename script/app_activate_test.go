package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestAppActivateClosedReceiverAndCapability(t *testing.T) {
	plan, err := Compile(`app("com.apple.mail").activate()`)
	if err != nil {
		t.Fatal(err)
	}
	step := plan.Steps[0]
	if step.Action != "app.activate" || step.Effect.Class != model.ExternalNonIdempotent || len(step.Effect.BusinessKey) == 0 {
		t.Fatalf("unsafe activation %+v", step)
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:appActivation": true}); err != nil {
		t.Fatal(err)
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:appLaunch": true}); err == nil {
		t.Fatal("launch-only capability accepted")
	}
	for _, source := range []string{`app("com.apple.mail").getById("x").activate()`, `app("com.apple.mail").window(title: "Inbox").activate()`, `web.tab(origin: "https://example.test").activate()`, `app("com.apple.mail").activate("x")`} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("invalid receiver accepted %s", source)
		}
	}
	step.Effect.BusinessKey = nil
	if err = step.Validate(); err == nil {
		t.Fatal("activation without business key accepted")
	}
}
