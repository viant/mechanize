package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestAppOpenUsesNativeLifecycleReceiverAndConservativeEffect(t *testing.T) {
	for _, source := range []string{`app("com.apple.mail").open()`, `let mail = app("com.apple.mail"); mail.open(timeout: 5s)`} {
		plan, err := Compile(source)
		if err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Action != "app.open" || plan.Steps[0].Effect.Class != model.ExternalNonIdempotent || plan.Steps[0].Target.Locator != nil || plan.Steps[0].Target.Surface.BundleID != "com.apple.mail" {
			t.Fatalf("bad lifecycle plan: %+v", plan)
		}
		if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:appLaunch": true}); err != nil {
			t.Fatal(err)
		}
		if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:semanticPress": true}); err == nil {
			t.Fatal("input capability qualified app launch")
		}
	}
	for _, source := range []string{`app("/Applications/Mail.app").open()`, `app("file:///Applications/Mail.app").open()`, `app("com.apple.mail").open("mailto:test@example.test")`, `app("com.apple.mail").getById("save").open()`, `app("com.apple.mail").window(title: "Inbox").open()`, `web.tab(origin: "https://example.test").open()`, `app("com.apple.mail").open().getById("save")`, `let result = app("com.apple.mail").open()`} {
		if _, err := Compile(source); err == nil {
			t.Fatalf("unsafe launch accepted: %s", source)
		}
	}
	for _, definition := range (Registry{}).Describe() {
		if definition.Action == "app.open" {
			if len(definition.Receivers) != 1 || definition.Receivers[0] != "app" || definition.Effect != model.ExternalNonIdempotent {
				t.Fatalf("bad registry %+v", definition)
			}
			return
		}
	}
	t.Fatal("launch not discovered")
}
