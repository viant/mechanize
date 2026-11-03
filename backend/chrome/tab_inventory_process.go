package chrome

import (
	"context"
	"errors"
)

// An operational inventory request may retire a peer whose fully verified
// identity contradicts its bound process identity. It never treats a timeout or missing
// observation as proof of change. Passive BrowserStatus remains non-mutating.
// The next connection must complete the normal signed handshake and recovery;
// no evidence, grants, private barriers or unresolved effects are rewritten here.
func (b *Broker) checkTabInventoryProcess(ctx context.Context, c *channel) error {
	b.mu.Lock()
	conn, epoch, evidence := c.conn, c.epoch, c.processEvidence
	b.mu.Unlock()
	err := b.checkChannelProcess(ctx, c, false)
	var diagnostic *channelProcessDiagnostic
	if err == nil || ctx.Err() != nil || !errors.As(err, &diagnostic) ||
		(diagnostic.reason != "chromeIdentityChanged" && diagnostic.reason != "nativeHostIdentityChanged") {
		return err
	}
	b.mu.Lock()
	same := c.conn == conn && c.epoch == epoch && c.processEvidence == evidence && !b.closed
	b.mu.Unlock()
	if same && conn != nil {
		_ = conn.Close()
	}
	return err
}
