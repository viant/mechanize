package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"testing"
	"time"
)

func focusedReply(r focusedLocationRequest) focusedLocationReply {
	return focusedLocationReply{Type: "focusedLocationResult", RequestID: r.RequestID, BrokerEpoch: r.BrokerEpoch, ChannelEpoch: r.ChannelEpoch, ScopeHash: r.ScopeHash, Available: true, WindowFocused: true, MatchesExpectedOrigin: true, Reason: "none", TabID: 7}
}
func TestFocusedLocationUsesMetadataOnlyWhilePrivateUnknownAndLifecycleRemain(t *testing.T) {
	g, p, ctx, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.focusedLocationVersion = 1
	c.unknown["retained"] = true
	c.lifecycleInhibited = true
	c.privateFlow = &credentialFlow{}
	g.broker.mu.Unlock()
	done := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			done <- e
			return
		}
		var r focusedLocationRequest
		if e = json.Unmarshal(raw, &r); e != nil {
			done <- e
			return
		}
		done <- WriteFrame(conn, focusedReply(r))
	}()
	out, e := g.MatchFocusedOrigin(ctx, p, c.grant.Origins[0])
	if e != nil || !out.Available || !out.MatchesExpectedOrigin || out.Evidence != "extensionFocusedTab" || out.TabHandle == "" {
		t.Fatal("metadata comparison failed", out, e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.executorQualified || c.inventoryComplete || !c.unknown["retained"] || !c.lifecycleInhibited || c.privateFlow == nil || c.privateFlow.poisoned {
		t.Fatal("metadata changed protected state")
	}
}
func TestFocusedLocationRefusesUnsupportedForeignAndMalformedReply(t *testing.T) {
	g, p, base, c, conn := setupFixture(t)
	out, e := g.MatchFocusedOrigin(base, p, c.grant.Origins[0])
	if e != nil || out.Reason != "unsupportedWorker" {
		t.Fatal(out, e)
	}
	foreign := p
	foreign.ClientID = "foreign"
	if _, e = g.MatchFocusedOrigin(base, foreign, c.grant.Origins[0]); e == nil {
		t.Fatal("borrowed another client")
	}
	if _, e = g.MatchFocusedOrigin(auth.WithPrincipal(base, p), p, c.grant.Origins[0]+"/private"); e == nil {
		t.Fatal("accepted path")
	}
	g.broker.mu.Lock()
	c.focusedLocationVersion = 1
	g.broker.mu.Unlock()
	go func() {
		raw, _ := ReadFrame(conn)
		var r focusedLocationRequest
		json.Unmarshal(raw, &r)
		reply, _ := json.Marshal(focusedReply(r))
		var values map[string]any
		json.Unmarshal(reply, &values)
		values["url"] = "PRIVATE-CANARY"
		WriteFrame(conn, values)
	}()
	ctx, cancel := context.WithTimeout(base, 60*time.Millisecond)
	defer cancel()
	out, e = g.MatchFocusedOrigin(ctx, p, c.grant.Origins[0])
	if e != nil || out.Available || out.Reason != "transportUnavailable" || out.TabHandle != "" {
		t.Fatal(out, e)
	}
}
