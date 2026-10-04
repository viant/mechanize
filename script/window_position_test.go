package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestWindowPositionTypedDSLAndCapabilities(t *testing.T) {
	source := `app("fixture.app", processId:1, processStartToken:"1:2").getByRole("window", name:"Finder", exact:true).moveTo({"x":100,"y":100})`
	plan, e := Compile(source)
	if e != nil {
		t.Fatal(e)
	}
	step := plan.Steps[0]
	if step.Action != "window.moveTo" || step.Arguments["position"].Kind != model.ObjectValue || step.Effect.Class != model.ExternalNonIdempotent {
		t.Fatalf("wrong contract %+v", step)
	}
	caps := map[string]bool{"native:roleLocator": true}
	if (Registry{}).CheckCapabilities(plan, caps) == nil {
		t.Fatal("unadvertised movement accepted")
	}
	caps["native:windowPosition"] = true
	if e = (Registry{}).CheckCapabilities(plan, caps); e != nil {
		t.Fatal(e)
	}
	for _, source := range []string{`app("fixture.app").getByRole("window").moveTo({"x":100,"y":100})`, `web.tab(origin:"https://example.com").getByRole("window").moveTo({"x":100,"y":100})`, `app("fixture.app",processId:1,processStartToken:"1:2").getByRole("window").moveTo({"x":100,"y":100,"z":0})`, `app("fixture.app",processId:1,processStartToken:"1:2").getByRole("window").moveTo("100,100")`, `app("fixture.app",processId:1,processStartToken:"1:2").getByRole("window").moveTo({x:100,y:100})`} {
		if _, e = Compile(source); e == nil {
			t.Fatal("invalid source accepted", source)
		}
	}
}
