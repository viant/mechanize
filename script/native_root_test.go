package script

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNativeRootDSLAndCapabilities(t *testing.T) {
	for _, root := range []string{"menuBar", "focusedElement"} {
		source := `app("com.apple.finder").` + root + `().getByRole("textbox", name: "Go to the folder:", exact: true).fill("/tmp")`
		plan, err := Compile(source)
		if err != nil {
			t.Fatal(err)
		}
		if plan.Steps[0].Target.Scope.NativeRoot != root || plan.Steps[0].Target.Locator == nil {
			t.Fatal("native root lost typed scope/locator")
		}
		caps := map[string]bool{"native:replaceValue": true, "native:roleLocator": true}
		if (Registry{}).CheckCapabilities(plan, caps) == nil {
			t.Fatal("unadvertised root capability accepted")
		}
		capability := map[string]string{"menuBar": "menuBarScope", "focusedElement": "focusedElementScope"}[root]
		caps["native:"+capability] = true
		if err = (Registry{}).CheckCapabilities(plan, caps); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(plan)
		decoded, err := DecodeJSON(bytes.NewReader(raw))
		if err != nil || decoded.Steps[0].Target.Scope.NativeRoot != root {
			t.Fatalf("native root JSON roundtrip: %v", err)
		}
		for _, tail := range []string{`("wrong").getById("x").read("name")`, `(scope: "x").getById("x").read("name")`, `().activate()`, `().open()`, `().fill("x")`, `().window(title: "Finder").getById("x").read("name")`, `().focusedElement().getById("x").read("name")`} {
			if _, err := Compile(`app("com.apple.finder").` + root + tail); err == nil {
				t.Fatal("invalid root expression accepted", tail)
			}
		}
	}
	for _, source := range []string{`web.tab(origin: "https://fixture.test").menuBar().getById("x").read("name")`, `app("com.apple.finder").window(title:"Finder").menuBar().getById("x").read("name")`, `app("com.apple.finder").getById("x").focusedElement().read("name")`, `expect(app("com.apple.finder").focusedElement()).toBeEnabled()`} {
		if _, err := Compile(source); err == nil {
			t.Fatal("invalid scoped receiver accepted", source)
		}
	}
	raw, _ := json.Marshal(EnvelopeSchema())
	if !strings.Contains(string(raw), `"nativeRoot"`) || !strings.Contains(string(raw), `"focusedElement"`) {
		t.Fatal("closed workflow schema lacks native root enum")
	}
}
