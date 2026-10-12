package script

import "testing"

func TestNativeIndexedRoleRequiresItsOwnCapabilityAndWindowBoundary(t *testing.T) {
	source := `app("com.microsoft.Excel", processId: 42, processStartToken: "100:1").window(title: "Sort").getByRole("AXPopUpButton", exact: true).nth(0, order: "tree").read("identifier")`
	plan, e := Compile(source)
	if e != nil {
		t.Fatal(e)
	}
	caps := map[string]bool{"native:attributeRead": true, "native:roleLocator": true, "native:windowScope": true, "native:indexedQuery": true}
	if e = (Registry{}).CheckCapabilities(plan, caps); e != nil {
		t.Fatal(e)
	}
	delete(caps, "native:indexedQuery")
	caps["native:orderedQuery"] = true
	if (Registry{}).CheckCapabilities(plan, caps) == nil {
		t.Fatal("generic plural capability enabled native indexed query")
	}
	caps["native:indexedQuery"] = true
	plan.Steps[0].Target.Scope.Window = nil
	if (Registry{}).CheckCapabilities(plan, caps) == nil {
		t.Fatal("global native ordinal enabled")
	}
}
