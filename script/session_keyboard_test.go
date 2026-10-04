package script

import "testing"

func TestSessionKeyboardIsExplicitNativeAction(t *testing.T) {
	p, err := Compile(`app("com.fixture.app", processId: 42, processStartToken: "100:1").getById("list", exact: true).pressSessionKey("Cmd+Shift+G")`)
	if err != nil || len(p.Steps) != 1 || p.Steps[0].Action != "element.pressSessionKey" {
		t.Fatalf("explicit route: %v", err)
	}
	for _, source := range []string{`app("com.fixture.app").getById("list", exact: true).pressSessionKey("Space")`, `web.tab(origin: "https://fixture.test").getById("list", exact: true).pressSessionKey("Space")`} {
		if _, err := Compile(source); err == nil {
			t.Fatal("unscoped/session web route accepted")
		}
	}
}
