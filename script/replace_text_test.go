package script

import "testing"

func TestReplaceTextExplicitNativeDSLAndCapability(t *testing.T) {
	source := `app("fixture.app",processId:1,processStartToken:"100:1").focusedElement().getByRole("textbox",name:"Path",exact:true).replaceText("literal")`
	plan, e := Compile(source)
	if e != nil {
		t.Fatal(e)
	}
	if plan.Steps[0].Action != "element.replaceText" {
		t.Fatal("replacement reinterpreted as fill")
	}
	caps := map[string]bool{"native:roleLocator": true, "native:focusedElementScope": true}
	if (Registry{}).CheckCapabilities(plan, caps) == nil {
		t.Fatal("unadvertised text setter accepted")
	}
	caps["native:replaceText"] = true
	if e = (Registry{}).CheckCapabilities(plan, caps); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{`app("fixture.app").getById("field").replaceText("literal")`, `web.tab(origin:"https://example.com").getById("field").replaceText("literal")`, `app("fixture.app",processId:1,processStartToken:"100:1").getById("field").replaceText(12)`} {
		if _, e = Compile(s); e == nil {
			t.Fatal("invalid replacement accepted", s)
		}
	}
}
