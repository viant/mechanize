package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestShowMenuIsDistinctFromPressAndRequiresItsCapability(t *testing.T) {
	plan, err := Compile(`app("com.microsoft.Powerpoint", processId: 123, processStartToken: "100:1").getByRole("AXMenuButton", name: "Paste", exact: true).showMenu()`)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Action != "element.showMenu" || plan.Steps[0].Effect.Class != model.ExternalNonIdempotent {
		t.Fatal("menu action reinterpreted")
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:semanticMenu": true, "native:roleLocator": true}); err != nil {
		t.Fatal(err)
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:semanticPress": true, "native:targetedKeyboard": true, "native:roleLocator": true}); err == nil {
		t.Fatal("press or keyboard authority enabled menu disclosure")
	}
	for _, source := range []string{`app("com.microsoft.Powerpoint").showMenu()`, `app("com.microsoft.Powerpoint").getById("paste").showMenu("AXPress")`} {
		if _, err := Compile(source); err == nil {
			t.Fatal("unsupported menu invocation accepted")
		}
	}
}
