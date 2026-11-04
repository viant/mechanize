package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestTextSelectionReadIsNativeBooleanAndCapabilityGated(t *testing.T) {
	plan, err := Compile(`let selected = app("com.example.Editor").getById("summary").read("hasFullTextSelection")`)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Steps[0].ResultType != model.BoolValue || plan.Steps[0].Effect.Class != model.ReadOnly {
		t.Fatal("selection read type/effect changed")
	}
	caps := map[string]bool{"native:attributeRead": true, "native:idLocator": true}
	if (Registry{}).CheckCapabilities(plan, caps) == nil {
		t.Fatal("unadvertised selection accepted")
	}
	caps["native:textSelectionObservation"] = true
	if err = (Registry{}).CheckCapabilities(plan, caps); err != nil {
		t.Fatal(err)
	}
	if _, err = Compile(`let selected = web.tab(origin:"https://example.test").getById("summary").read("hasFullTextSelection")`); err == nil {
		t.Fatal("native selection leaked to web")
	}
}
