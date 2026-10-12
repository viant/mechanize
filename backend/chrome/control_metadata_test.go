package chrome

import (
	"github.com/viant/mechanize/model"
	"testing"
)

func TestControlAdmissionUsesMetadataWhenSourceCannotBeObserved(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2, func() string { return "noObservation" })
	surface := model.Surface{Kind: "web", Origin: "https://fixture.test"}
	if _, e := g.Observe(ctx, p, surface); e == nil {
		t.Fatal("fixture unexpectedly allowed DOM observation")
	}
	admission, e := g.AdmitControlWithStatus(ctx, p, surface)
	if e != nil || !admission.Confirmed || !admission.Created {
		t.Fatal("metadata-only admission refused", e)
	}
	if count.Load() != 0 {
		t.Fatal("binding dispatched input")
	}
	if ok, e := g.RetireControl(ctx, p, admission.Authority); e != nil || !ok {
		t.Fatal("exact metadata-bound lease did not retire", e)
	}
}
