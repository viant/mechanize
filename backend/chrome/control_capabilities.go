package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strconv"
)

// ControlCapabilitiesFor reports transport support from owned signed metadata.
// It never acquires a renderer lease, reads DOM values or sends input. Prepare
// must independently admit the selected document and human consent afterward.
func (g *Gateway) ControlCapabilitiesFor(ctx context.Context, p auth.Principal) (map[string]bool, error) {
	if err := authorize(ctx, p, true); err != nil {
		return nil, err
	}
	actual, err := auth.FromContext(ctx)
	if err != nil || actual.ClientID != p.ClientID {
		return nil, auth.ErrUnauthorized
	}
	result := map[string]bool{}
	if g == nil || g.broker == nil {
		return result, nil
	}
	var surfaces []model.Surface
	g.broker.mu.Lock()
	for _, c := range g.broker.channels {
		if c.grant.Principal.Namespace != p.Namespace || c.conn == nil || c.fixtureOnly || !channelScopeQualified(c) || !c.executorQualified || !c.inventoryComplete {
			continue
		}
		for _, d := range c.documents {
			// A newly navigated document is advertised before its packaged
			// executor has been bound. Capability discovery describes the v2
			// transport; admission must still bind and verify the exact document.
			if d.FrameID == 0 && c.mutationFingerprintVersion == 2 && (d.MutationFingerprintVersion == 1 || d.MutationFingerprintVersion == 2) && allowedOrigin(c.grant, d.Origin) {
				surfaces = append(surfaces, model.Surface{Kind: "web", Origin: d.Origin, TabID: strconv.Itoa(d.TabID)})
			}
		}
	}
	g.broker.mu.Unlock()
	for _, surface := range surfaces {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		authority, _, err := g.controlMetadataSnapshot(ctx, p, surface, false)
		if err != nil || authority.MutationFingerprintVersion != 2 {
			continue
		}
		for _, name := range []string{"semanticPress", "element.press", "replaceValue", "element.fill", "browser.activate", "roleLocator", "idLocator", "testIdLocator", "labelRelationships"} {
			result["web:"+name] = true
		}
		if authority.SelectOptionVersion == 1 {
			result["web:selectOption"], result["web:element.select"] = true, true
		}
		if authority.AllWebsites {
			result["web:browser.navigate"] = true
		}
	}
	return result, nil
}
