package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

func TestControlCapabilityDiscoveryHandlesMultipleTabsWithoutRendererAdmission(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey("p1", "b1")]
	second := c.documents[0]
	second.TabID = 8
	second.DocumentID = "doc2"
	c.documents = append(c.documents, second)
	g.broker.mu.Unlock()
	caps, err := g.ControlCapabilitiesFor(ctx, p)
	if err != nil || !caps["web:semanticPress"] || caps["web:browser.navigate"] {
		t.Fatal(caps, err)
	}
	if count.Load() != 0 {
		t.Fatal("capability discovery sent a command")
	}
	g.controlMu.Lock()
	held := testFirstControl(g) != nil
	g.controlMu.Unlock()
	if held {
		t.Fatal("capability discovery acquired a renderer lease")
	}
	_, _, err = g.controlSnapshot(ctx, p, model.Surface{Kind: "web", Origin: "https://fixture.test"})
	if err == nil {
		t.Fatal("unscoped dispatch lost ambiguity check")
	}
}

func TestNewDocumentAdvertisesNegotiatedTransportWithoutDOMObservation(t *testing.T) {
	g, p, ctx, count := controlFixtureVersion(t, 2)
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey("p1", "b1")]
	c.documents[0].MutationFingerprintVersion = 1
	g.broker.mu.Unlock()
	caps, err := g.ControlCapabilitiesFor(ctx, p)
	if err != nil || caps["web:browser.navigate"] || !caps["web:semanticPress"] || count.Load() != 0 {
		t.Fatal("new document required an ordinary DOM read before binding", caps, err)
	}
	g.broker.mu.Lock()
	c.mutationFingerprintVersion = 1
	g.broker.mu.Unlock()
	caps, err = g.ControlCapabilitiesFor(ctx, p)
	if err != nil || caps["web:browser.navigate"] || caps["web:semanticPress"] {
		t.Fatal("unnegotiated worker advertised mutation support", caps, err)
	}
}

func TestPrivateDOMCapabilityMetadataRequiresPublishedOwnedProofButNoExecutionBinding(t *testing.T) {
	g, p, ctx, source, submit := privacyFixture(t)
	proof, e := g.QualifyCredentialPrivacy(ctx, p, source, submit, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	_, ok := proof.Authority()
	if !ok {
		t.Fatal("missing production privacy proof")
	}
	unbound := auth.WithPrincipal(context.Background(), p)
	caps, e := g.ControlCapabilitiesFor(unbound, p)
	if e != nil || !caps["web:semanticPress"] {
		t.Fatal("owned metadata discovery required execution binding", caps, e)
	}
	foreign := p
	foreign.ClientID = "foreign-client"
	other, e := g.ControlCapabilitiesFor(auth.WithPrincipal(context.Background(), foreign), foreign)
	if e != nil || other["web:semanticPress"] {
		t.Fatal("foreign client borrowed private metadata", other, e)
	}
	g.broker.mu.Lock()
	c := g.broker.channels[channelKey(source.Document.ProfileChannel, source.Document.BrowserInstance)]
	c.privacy.active = false
	g.broker.mu.Unlock()
	caps, e = g.ControlCapabilitiesFor(unbound, p)
	if e != nil || caps["web:semanticPress"] {
		t.Fatal("withdrawn proof still advertised control", caps, e)
	}
}
