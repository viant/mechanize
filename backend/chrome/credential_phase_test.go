package chrome

import (
	"context"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
)

func TestPrivateAdmissionIdentifiesRetainedAuthorityWithoutRendererProbe(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "fixture"})
	g.controlMu.Lock()
	testMarkControlRetiring(g)
	g.controlMu.Unlock()
	result, err := g.AdmitCredentialControl(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"}, func(context.Context) error { return nil })
	if err == nil || result.Confirmed || result.Created || result.FailureStage != "authority" || count.Load() != 0 {
		t.Fatal("retained authority was not distinguished before private input", result, err)
	}
}
