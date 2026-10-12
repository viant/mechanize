package script

import "testing"

func TestCanonicalActivationDoesNotAdvertiseUnsupportedDSL(t *testing.T) {
	for _, d := range (Registry{}).Describe() {
		if d.Name == "" || d.Action == "browser.activateTab" {
			t.Fatal("canonical-only action advertised as DSL", d)
		}
	}
	plan, e := Compile(`web.tab(origin: "https://fixture.test").activateTab()`)
	if e != nil || len(plan.Steps) != 1 || plan.Steps[0].Action != "browser.activate" {
		t.Fatal("existing renderer DSL changed", e)
	}
}
