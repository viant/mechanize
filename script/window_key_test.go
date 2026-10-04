package script

import "testing"

func TestPressWindowKeyNamedNativeAppArguments(t *testing.T) {
	source := `app("fixture.app",processId:1,processStartToken:"100:1").pressWindowKey(windowId:9625,key:"Escape")`
	plan, e := Compile(source)
	if e != nil {
		t.Fatal(e)
	}
	step := plan.Steps[0]
	if step.Action != "window.pressSessionKey" || step.Target.Locator != nil || step.Arguments["windowKey"].Object["windowId"].Number != 9625 {
		t.Fatal("action reinterpreted", step)
	}
	if (Registry{}).CheckCapabilities(plan, map[string]bool{}) == nil {
		t.Fatal("unadvertised action accepted")
	}
	if e = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:windowSessionKeyboard": true}); e != nil {
		t.Fatal(e)
	}
	for _, source := range []string{`app("fixture.app").pressWindowKey(windowId:9625,key:"Escape")`, `app("fixture.app",processId:1,processStartToken:"100:1").focusedElement().pressWindowKey(windowId:9625,key:"Escape")`, `app("fixture.app",processId:1,processStartToken:"100:1").getById("field").pressWindowKey(windowId:9625,key:"Escape")`, `app("fixture.app",processId:1,processStartToken:"100:1").pressWindowKey(windowId:9625)`, `app("fixture.app",processId:1,processStartToken:"100:1").pressWindowKey(windowId:0,key:"Escape")`, `app("fixture.app",processId:1,processStartToken:"100:1").pressWindowKey(windowId:9625,key:"Escape",text:"unsafe")`} {
		if _, e = Compile(source); e == nil {
			t.Fatal("invalid window keyboard source accepted", source)
		}
	}
}
