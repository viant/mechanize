package host

import (
	"context"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/script"
)

func TestWebReadPolicyDoesNotProbeNativeOrAdmitMutation(t *testing.T) {
	q := newObservationPolicyFixture(t, true)
	readPlan, err := script.Compile(`let value=web.tab(origin:"https://fixture.test").getById("public").read("value")`)
	if err != nil {
		t.Fatal(err)
	}
	// This fixture intentionally has no production-qualified read channel. Its
	// refusal must not start native discovery while validating the web step.
	if _, err = q.h.execute(q.f.ctx, q.f.principal, readPlan.Steps[0], nil); err == nil {
		t.Fatal("fixture channel unexpectedly qualified")
	}
	policy, err := q.h.webReadPolicy(q.f.ctx, q.f.principal)
	if err != nil {
		t.Fatal(err)
	}
	if q.read.doctors.Load() != 0 || q.f.starts != 0 || q.f.calls != 0 {
		t.Fatal("web read policy touched native runtime")
	}
	if policy.AllowMutation || policy.AllowAllNative || !policy.AllowedSurfaces["https://fixture.test"] {
		t.Fatal("read scope changed")
	}
	plan, err := script.Compile(`web.tab(origin:"https://fixture.test").getById("save").click()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = (script.Validator{}).CheckPolicy(plan, policy); err == nil {
		t.Fatal("read policy admitted mutation")
	}
	canceled, cancel := context.WithCancel(q.f.ctx)
	cancel()
	if _, err = q.h.webReadPolicy(canceled, q.f.principal); err == nil {
		t.Fatal("canceled policy accepted")
	}
	foreign := q.f.principal
	foreign.ClientID = "different-client"
	if _, err = q.h.webReadPolicy(auth.WithPrincipal(q.f.ctx, foreign), q.f.principal); err == nil {
		t.Fatal("foreign actor accepted")
	}
}
