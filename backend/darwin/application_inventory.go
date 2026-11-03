package darwin

import (
	"context"
	"github.com/viant/mechanize/model"
)

func (g *Gateway) applicationInventory(ctx context.Context, surface model.Surface) (Reply, error) {
	if g.applicationLookupEnabled && surface.ProcessID > 0 {
		return g.call(ctx, "app.lookup", map[string]any{"expectedApp": surface.BundleID,
			"pid": surface.ProcessID, "startToken": surface.ProcessStartToken,
			"launchTime": "kernel:" + surface.ProcessStartToken}, nil)
	}
	return g.call(ctx, "apps.list", map[string]any{"expectedApp": surface.BundleID}, nil)
}
