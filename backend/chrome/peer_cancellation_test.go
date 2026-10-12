package chrome

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestCancelledPeerProbeDeniesOperationWithoutDestroyingPrivateChannel(t *testing.T) {
	g, _, _, _ := controlFixtureVersion(t, 2)
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	conn := c.conn
	inspection := &credentialAdmissionPending{done: make(chan credentialAdmissionReply, 1)}
	c.privateInspection = inspection
	b.mu.Unlock()
	b.verifyPeer = func(ctx context.Context, _ *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		<-ctx.Done()
		return nativepeer.ChromeProcessEvidence{}, ctx.Err()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := b.verifyChannelProcess(ctx, c); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cancelled verification did not deny operation", err)
	}
	if _, err := conn.Write(nil); err != nil {
		t.Fatal("deadline destroyed authenticated transport", err)
	}
	b.mu.Lock()
	retained := c.conn == conn && c.privateInspection == inspection
	b.mu.Unlock()
	if !retained {
		t.Fatal("deadline discarded private protection")
	}
}

func TestChangedPeerStillRevokesChannel(t *testing.T) {
	g, _, _, _ := controlFixtureVersion(t, 2)
	b := g.broker
	b.mu.Lock()
	c := b.channels[channelKey("p1", "b1")]
	conn := c.conn
	changed := *c.processEvidence
	changed.NativeHost.StartToken = "different-process"
	b.mu.Unlock()
	b.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return changed, nil }
	if err := b.verifyChannelProcess(context.Background(), c); err == nil {
		t.Fatal("changed peer admitted")
	}
	if _, err := conn.Write(nil); err == nil {
		t.Fatal("changed peer kept live transport")
	}
}
