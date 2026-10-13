package chrome

import (
	"context"
	"github.com/viant/mechanize/auth"
	"strings"
	"testing"
)

func TestControllerAbsenceExaminesEveryOwnedChannelAndRetainsUncertainty(t *testing.T) {
	p := principal(t, "owner-absence")
	p.ClientID = "successor"
	first, second := enrollment(p, "first"), enrollment(p, "second")
	b := fixtureBroker(t, first, second)
	g, e := NewGateway(b, GatewayOptions{})
	if e != nil {
		t.Fatal(e)
	}
	ctx := auth.WithPrincipal(context.Background(), p)
	old := "controller:" + strings.Repeat("a", 64)
	c := b.channels[channelKey(second.ProfileChannel, second.BrowserInstance)]
	if c == nil {
		c = &channel{grant: second}
		b.channels[channelKey(second.ProfileChannel, second.BrowserInstance)] = c
	}
	owner := p
	owner.ClientID = old
	c.controllerSessions = map[string]*ControllerSession{"old": {identity: ControllerIdentity{Principal: owner}}}
	if g.VerifyControllerOwnerAbsent(ctx, p, old) == nil {
		t.Fatal("live controller on another owned channel was ignored")
	}
	delete(c.controllerSessions, "old")
	c.controllerCleanupPending = true
	if g.VerifyControllerOwnerAbsent(ctx, p, old) == nil {
		t.Fatal("unfinished controller cleanup was ignored")
	}
	c.controllerCleanupPending = false
	if g.VerifyControllerOwnerAbsent(ctx, p, old) != nil {
		t.Fatal("absent controller refused")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if g.VerifyControllerOwnerAbsent(canceled, p, old) == nil {
		t.Fatal("canceled absence claim accepted")
	}
	if g.VerifyControllerOwnerAbsent(ctx, p, "controller:invalid") == nil {
		t.Fatal("unqualified owner accepted")
	}
}
