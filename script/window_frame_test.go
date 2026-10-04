package script

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestWindowFrameClickClosedDSL(t *testing.T) {
	source := `let office=app("fixture.app",processId:42,processStartToken:"100:1"); office.clickWindowFrame(captureRef:$input.frame,x:420,y:27)`
	plan, err := Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Action != "window.clickFrame" || plan.Steps[0].Effect.Class != model.ExternalNonIdempotent {
		t.Fatalf("wrong action: %+v", plan)
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:windowFrameClick": true}); err != nil {
		t.Fatal(err)
	}
	if err = (Registry{}).CheckCapabilities(plan, map[string]bool{"native:semanticPress": true}); err == nil {
		t.Fatal("semantic capability granted pointer action")
	}
	args, err := plan.Steps[0].ResolveArguments(map[string]model.Value{"input.frame": {Kind: model.StringValue, String: "issued-permit"}})
	if err != nil {
		t.Fatal(err)
	}
	ref, x, y, err := model.WindowFrameClick(args["frameClick"])
	if err != nil || ref != "issued-permit" || x != 420 || y != 27 {
		t.Fatal("typed frame arguments changed")
	}
	for _, bad := range []string{
		`app("fixture.app").clickWindowFrame(captureRef:"permit",x:1,y:2)`,
		`app("fixture.app",processId:42,processStartToken:"100:1").getById("button").clickWindowFrame(captureRef:"permit",x:1,y:2)`,
		`app("fixture.app",processId:42,processStartToken:"100:1").clickWindowFrame(captureRef:"permit",x:1,y:2,button:"right")`,
		`app("fixture.app",processId:42,processStartToken:"100:1").clickWindowFrame(captureRef:"permit",x:-1,y:2)`,
		`app("fixture.app",processId:42,processStartToken:"100:1").clickWindowFrame(captureRef:"permit",x:1,y:32768)`,
		`app("fixture.app",processId:42,processStartToken:"100:1").clickWindowFrame(captureRef:"permit",x:1)`,
	} {
		if _, err := Compile(bad); err == nil {
			t.Fatalf("unsafe DSL accepted: %s", bad)
		}
	}
}
