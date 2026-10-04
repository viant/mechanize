package script

import "testing"

func TestNativeIdentifierAndRoleReads(t *testing.T) {
	for _, attribute := range []string{"identifier", "role"} {
		p, err := Compile(`let metadata = app("com.fixture.app").getById("target", exact: true).read("` + attribute + `")`)
		if err != nil || p.Steps[0].ResultType != "string" {
			t.Fatalf("native metadata %s: %v", attribute, err)
		}
		if _, err := Compile(`web.tab(origin: "https://fixture.test").getById("target", exact: true).read("` + attribute + `")`); err == nil {
			t.Fatal("native read widened to web")
		}
	}
}

func TestNativeEnabledReadIsBooleanAndNativeOnly(t *testing.T) {
	p, err := Compile(`let enabled = app("com.fixture.app").getById("target", exact: true).read("enabled")`)
	if err != nil || p.Steps[0].ResultType != "boolean" {
		t.Fatalf("native enabled read: %v", err)
	}
	if _, err := Compile(`web.tab(origin: "https://fixture.test").getById("target", exact: true).read("enabled")`); err == nil {
		t.Fatal("native boolean read widened to web")
	}
}
