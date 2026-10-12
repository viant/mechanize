package chrome

import (
	"strings"
	"testing"
)

func TestStatusRefreshQueriesOnlyOriginalReceiptAndPreservesFingerprintFence(t *testing.T) {
	for _, mode := range []string{"matching", "wrongReceiptFingerprint"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, inputs := controlFixtureVersion(t, 2, func() string { return mode })
			b := g.broker
			b.mu.Lock()
			c := b.channels[channelKey("p1", "b1")]
			id := strings.Repeat("a", 64)
			c.attempts[id] = Command{Action: "element.press", Identity: c.documents[0].Identity, AttemptID: id, FingerprintVersion: 2, FingerprintSHA256: strings.Repeat("b", 64), BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}
			c.unknown[id] = true
			b.mu.Unlock()
			status, err := g.BrowserStatus(ctx, p)
			if err != nil || len(status.Channels) != 1 {
				t.Fatal(status, err)
			}
			expected := 0
			if mode != "matching" {
				expected = 1
			}
			if status.Channels[0].UnknownCount != expected {
				t.Fatal("receipt fingerprint fence", status)
			}
			if inputs.Load() != 0 {
				t.Fatal("status refresh replayed input")
			}
		})
	}
}
