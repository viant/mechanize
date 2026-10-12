package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestWindowTextUsesClosedAppActionAndOwnCapability(t *testing.T) {
	source := `app("com.microsoft.Excel",processId:1,processStartToken:"100:1").typeWindowText(windowId:42,text:"=SUM(17,23)",focusRole:"AXLayoutArea",focusName:"Content Area")`
	plan, err := Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Steps[0].Action != "window.typeText" || plan.Steps[0].Effect.Class != model.ExternalNonIdempotent {
		t.Fatal("wrong action")
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:windowSessionKeyboard": true}); err == nil {
		t.Fatal("keyboard route silently enabled text")
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:windowSessionText": true}); err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{`app("com.microsoft.Excel").typeWindowText(windowId:42,text:"x",focusRole:"AXTextField",focusName:"input")`, `app("com.microsoft.Excel",processId:1,processStartToken:"100:1").typeWindowText(windowId:42,text:"x",focusRole:"AXTextField")`, `app("com.microsoft.Excel",processId:1,processStartToken:"100:1").focusedElement().typeWindowText(windowId:42,text:"x",focusRole:"AXTextField",focusName:"input")`} {
		if _, err = Compile(src); err == nil {
			t.Fatal("invalid text action accepted")
		}
	}
}
