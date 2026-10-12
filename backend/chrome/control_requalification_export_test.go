package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"testing"
)

// Test-only socket-backed gateway, shared with the external Host integration.
func ControlRequalificationFixtureForTest(t *testing.T) (*Gateway, context.Context, auth.Principal, model.Surface, func(), func() bool, func() (int64, int64)) {
	f := newReadFixture(t)
	f.g.broker.mu.Lock()
	c := f.g.broker.channels[channelKey("p1", "b1")]
	c.receipts["retained-known"] = Reply{AttemptID: "retained-known", DispatchState: "dispatched", EffectState: "unverified"}
	f.g.broker.mu.Unlock()
	return f.g, f.ctx, f.p, readTarget().Surface, func() {
			generation := f.generation.Add(1)
			f.g.broker.mu.Lock()
			for i := range c.documents {
				c.documents[i].Generation = generation
			}
			f.g.broker.mu.Unlock()
		}, func() bool {
			f.g.broker.mu.Lock()
			defer f.g.broker.mu.Unlock()
			r := c.receipts["retained-known"]
			return r.AttemptID == "retained-known" && r.DispatchState == "dispatched" && r.EffectState == "unverified" && f.reads.Load() == 0
		}, func() (int64, int64) { return f.acquireCalls.Load(), f.mutations.Load() }
}
