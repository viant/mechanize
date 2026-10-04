package session

import (
	"encoding/json"
	"testing"
)

func TestDesktopScopeIsTypedAndRejectsWildcardAndMixedAuthority(t *testing.T) {
	all, err := (Scope{AllApplications: true}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	for _, bundle := range []string{"com.apple.mail", "com.apple.TextEdit", "com.new.installation"} {
		if !all.AllowsBundle(bundle) {
			t.Fatalf("new app blocked %s", bundle)
		}
	}
	for _, bundle := range []string{"*", "", "/Applications/Mail.app", "file:///Applications/Mail.app", "com.apple.mail\nother"} {
		if all.AllowsBundle(bundle) {
			t.Fatalf("unsafe target %q", bundle)
		}
	}
	for _, scope := range []Scope{{}, {AllowedBundles: []string{"*"}}, {AllApplications: true, AllowedBundles: []string{"com.apple.mail"}}, {AllowedBundles: []string{"com.apple.mail", "com.apple.mail"}}} {
		if _, err := scope.Normalize(); err == nil {
			t.Fatalf("unsafe scope %+v", scope)
		}
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"allApplications":true,"allowedBundles":[]}` {
		t.Fatalf("wrong fence encoding %s", raw)
	}
	var claimed Scope
	if json.Unmarshal([]byte(`{"allApplications":1,"allowedBundles":[]}`), &claimed) == nil {
		t.Fatal("number minted boolean authority")
	}
	if all.Equal(Scope{AllowedBundles: []string{"com.apple.mail"}}) {
		t.Fatal("desktop and restricted scopes compare equal")
	}
}
func TestSupervisorDesktopScopeRetainsSameEpochAndCannotChangeMode(t *testing.T) {
	options, _, _ := fixtureOptions(t)
	supervisor, err := NewSupervisor(options)
	if err != nil {
		t.Fatal(err)
	}
	ctx, p := supervisorActor(t, "alice")
	defer supervisor.Close(ctx)
	first, err := supervisor.Acquire(ctx, p, Scope{AllApplications: true})
	if err != nil {
		t.Fatal(err)
	}
	if !first.Scope.AllowsBundle("com.new.installedApp") {
		t.Fatal("app inventory froze desktop access")
	}
	first.Scope.AllApplications = false
	first.Scope.AllowedBundles = append(first.Scope.AllowedBundles, "forged.app")
	next, err := supervisor.Acquire(ctx, p, Scope{AllApplications: true})
	if err != nil {
		t.Fatal(err)
	}
	if next.Generation != first.Generation || next.ID != first.ID || !next.Scope.AllApplications || len(next.Scope.AllowedBundles) != 0 {
		t.Fatalf("desktop lease changed %+v", next)
	}
	if _, err := supervisor.Acquire(ctx, p, Scope{AllowedBundles: []string{"com.apple.mail"}}); err == nil {
		t.Fatal("scope narrowed silently without explicit transfer")
	}
}
