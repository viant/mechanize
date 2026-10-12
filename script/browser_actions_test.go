package script

import "testing"

func TestCanonicalBrowserPageActions(t *testing.T) {
	for source, action := range map[string]string{`web.tab(origin: "https://fixture.test").navigate("https://fixture.test/next")`: "browser.navigate", `web.tab(origin: "https://fixture.test").activateTab()`: "browser.activate"} {
		plan, err := Compile(source)
		if err != nil {
			t.Fatal(err)
		}
		s := plan.Steps[0]
		if s.Action != action || s.Target.Locator != nil {
			t.Fatal("browser action not canonical")
		}
	}
	for _, source := range []string{`app("fixture.app").navigate("https://fixture.test")`, `web.tab(origin: "https://fixture.test").getById("x").activateTab()`, `web.tab(origin: "https://fixture.test").navigate("javascript:alert(1)")`, `web.tab(origin: "https://fixture.test").navigate("https://user:password@fixture.test")`, `web.tab(origin: "https://fixture.test").navigate("https://fixture.test/?token=x")`} {
		if _, err := Compile(source); err == nil {
			t.Fatal("unsafe/nonpage navigation accepted", source)
		}
	}
}

func TestOpenOriginIsSourceIndependentBoundedMutation(t *testing.T) {
	for _, source := range []string{`let tab = web.tab(origin: "https://fixture.test").openOrigin()`, `web.tab(origin: "http://127.0.0.1:8080").openOrigin()`} {
		p, e := Compile(source)
		if e != nil {
			t.Fatal(e)
		}
		s := p.Steps[0]
		if s.Action != "browser.openOrigin" || s.Target.Surface.TabID != "" || s.Target.Locator != nil || s.TimeoutMs != 3000 || len(s.Effect.BusinessKey) == 0 || s.ResultType != "string" {
			t.Fatal("open origin lost closed action contract", s)
		}
	}
	for _, source := range []string{`web.tab(origin: "https://fixture.test/path").openOrigin()`, `web.tab(origin: "https://fixture.test/").openOrigin()`, `web.tab(origin: "https://user:password@fixture.test").openOrigin()`, `web.tab(origin: "https://fixture.test?x=1").openOrigin()`, `web.tab(origin: "https://fixture.test#x").openOrigin()`, `web.tab(origin: "https://fixture.test").getById("x").openOrigin()`, `app("fixture.app").openOrigin()`} {
		if _, e := Compile(source); e == nil {
			t.Fatal("non-origin or source-scoped opener accepted", source)
		}
	}
}
