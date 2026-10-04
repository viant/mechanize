package script

import "testing"

func TestExplicitFocusAndKeyboardRequireSeparateCommands(t *testing.T) {
	plan, err := Compile(`app("com.google.Chrome", processId: 4464, processStartToken: "100:1").getById("developer", exact: true).focus(); app("com.google.Chrome", processId: 4464, processStartToken: "100:1").getById("developer", exact: true).pressKey("Space")`)
	if err != nil || len(plan.Steps) != 2 || plan.Steps[0].Action != "element.focus" || plan.Steps[1].Action != "element.pressKey" {
		t.Fatalf("explicit typed focus/key compile: %v", err)
	}
}
func TestNativeFocusedReadHasBooleanTypeWithoutNewInputAuthority(t *testing.T) {
	plan, err := Compile(`let focused = app("com.google.Chrome", processId: 4464, processStartToken: "100:1").getById("developer", exact: true).read("focused")`)
	if err != nil || len(plan.Steps) != 1 || plan.Steps[0].ResultType != "boolean" {
		t.Fatalf("native focused read: %v", err)
	}
	if _, err = Compile(`web.tab(origin: "https://fixture.test").getById("field", exact: true).read("focused")`); err == nil {
		t.Fatal("unqualified web focused read accepted")
	}
}
