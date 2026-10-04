package chrome

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/script"
)

func scopedCapabilityMap(t *testing.T, g *Gateway, ctx context.Context, p auth.Principal) map[string]bool {
	t.Helper()
	capabilities, err := g.CapabilitiesFor(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]bool{}
	for _, capability := range capabilities {
		result[capability.Surface+":"+capability.Name] = capability.Supported
	}
	return result
}

func TestActorScopedChromeCapabilitiesValidateCanonicalReadonlyDSLWithoutControl(t *testing.T) {
	for _, scope := range []string{TrustScopeProfile, TrustScopeDesktop} {
		t.Run(scope, func(t *testing.T) {
			f := newReadFixtureScope(t, scope)
			p := f.p
			p.Scopes = []string{"desktop:observe"}
			ctx := auth.WithPrincipal(context.Background(), p)
			caps := scopedCapabilityMap(t, f.g, ctx, p)
			for _, name := range []string{"attributeRead", "boundedObservation", "roleLocator", "idLocator", "testIdLocator", "labelRelationships"} {
				if !caps["web:"+name] {
					t.Fatalf("missing read capability %s", name)
				}
			}
			for _, name := range []string{"element.press", "element.fill", "browser.navigate", "recording", "nameLocator", "textLocator", "frameScope", "windowScope", "ancestorScope", "orderedQuery", "checkedObservation"} {
				if caps["web:"+name] {
					t.Fatalf("unqualified route advertised: %s", name)
				}
			}
			plan, err := script.Compile(`let answer=web.tab(origin:"https://fixture.test").getById("counter",exact:true).read("text")`)
			if err != nil {
				t.Fatal(err)
			}
			policy := script.Policy{AllowedSurfaces: map[string]bool{"https://fixture.test": true}, Capabilities: caps, AllowMutation: false}
			if err := (script.Validator{}).CheckPolicy(plan, policy); err != nil {
				t.Fatal(err)
			}
			if f.g.options.Lease != nil {
				t.Fatal("fixture unexpectedly supplied mutation control")
			}
			if _, err := f.g.Execute(ctx, p, plan.Steps[0], nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestActorScopedChromeCapabilitiesDoNotLeakOtherOwnerOrUnqualifiedChannels(t *testing.T) {
	for _, mode := range []string{"other owner", "no documents", "unqualified scope", "unqualified executor", "incomplete inventory", "only child frame", "fixture", "closed", "missing gateway"} {
		t.Run(mode, func(t *testing.T) {
			f := newReadFixture(t)
			p, ctx, g := f.p, f.ctx, f.g
			if mode == "other owner" {
				p, _ = auth.NewPrincipal("fixture", "", "different", []string{"desktop:observe"})
				ctx = auth.WithPrincipal(context.Background(), p)
			} else {
				g.broker.mu.Lock()
				c := g.broker.channels[channelKey("p1", "b1")]
				switch mode {
				case "no documents":
					c.documents = nil
				case "unqualified scope":
					c.scopeQualified = false
				case "unqualified executor":
					c.executorQualified = false
				case "incomplete inventory":
					c.inventoryComplete = false
				case "only child frame":
					c.documents[0].FrameID = 1
				case "fixture":
					c.fixtureOnly = true
				case "closed":
					g.broker.closed = true
					t.Cleanup(func() { g.broker.mu.Lock(); g.broker.closed = false; g.broker.mu.Unlock() })
				case "missing gateway":
				}
				g.broker.mu.Unlock()
				if mode == "missing gateway" {
					g = &Gateway{}
				}
			}
			for _, supported := range scopedCapabilityMap(t, g, ctx, p) {
				if supported {
					t.Fatal("unowned/unqualified channel exposed capabilities")
				}
			}
		})
	}
}

func TestActorScopedChromeCapabilitiesRejectForgedActorAndCancellation(t *testing.T) {
	f := newReadFixture(t)
	for _, mode := range []string{"namespace", "client", "cancelled"} {
		p, ctx := f.p, f.ctx
		switch mode {
		case "namespace":
			p.Namespace = "forged"
		case "client":
			p.ClientID = "different"
		case "cancelled":
			var cancel context.CancelFunc
			ctx, cancel = context.WithCancel(ctx)
			cancel()
		}
		caps, err := f.g.CapabilitiesFor(ctx, p)
		if err == nil || len(caps) != 0 {
			t.Fatal("unverified capability request accepted")
		}
		if mode == "cancelled" && !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation lost")
		}
	}
}
