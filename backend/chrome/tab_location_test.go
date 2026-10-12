package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

func TestExpectedTabPathCanonical(t *testing.T) {
	for _, s := range []string{"/../x", "/%2e%2e/x", "/x/%2E", "/%00", "/%0a", "/%7f", "/%C2%85", "/x?key=value", "/x#y", "//foreign", "/x\\y", "/x\x01", "/%zz"} {
		if ValidExpectedTabPath("https://fixture.test", s) {
			t.Fatal("unsafe path accepted")
		}
	}
	for _, s := range []string{"", "/", "/public/error", "/encoded%20path"} {
		if !ValidExpectedTabPath("https://fixture.test", s) {
			t.Fatal("public path rejected")
		}
	}
}
func TestMatchTabLocationWhileProtectedWithoutPublicDocuments(t *testing.T) {
	g, p, ctx, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.tabMetadataVersion = 1
	c.privateFlow = &credentialFlow{}
	c.unknown["retained"] = true
	c.lifecycleInhibited = true
	g.broker.mu.Unlock()
	handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
	go func() {
		raw, _ := ReadFrame(conn)
		var q tabLocationRequest
		json.Unmarshal(raw, &q)
		WriteFrame(conn, tabLocationReply{Type: "tabLocationResult", RequestID: q.RequestID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, TabLocationMatch: TabLocationMatch{Available: true, MatchesExpectedOrigin: true, PathChecked: true, MatchesExpectedPath: true, Reason: "none"}})
	}()
	r, e := g.MatchTabLocation(ctx, p, handle, c.grant.Origins[0], "/public/error")
	if e != nil || !r.MatchesExpectedPath {
		t.Fatal(r, e)
	}
	g.broker.mu.Lock()
	retained := c.privateFlow != nil && c.unknown["retained"] && c.lifecycleInhibited && len(c.documents) == 0
	g.broker.mu.Unlock()
	if !retained {
		t.Fatal("metadata altered protection")
	}
}
func TestTabLocationMalformedForeignAndUnsupportedAreClosed(t *testing.T) {
	g, p, base, c, conn := setupFixture(t)
	handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
	r, e := g.MatchTabLocation(base, p, handle, c.grant.Origins[0], "")
	if e != nil || r.Reason != "unsupportedWorker" {
		t.Fatal(r, e)
	}
	foreign := p
	foreign.ClientID = "foreign"
	if _, e = g.MatchTabLocation(auth.WithPrincipal(base, p), foreign, handle, c.grant.Origins[0], ""); e == nil {
		t.Fatal("foreign actor")
	}
	g.broker.mu.Lock()
	c.tabMetadataVersion = 1
	g.broker.mu.Unlock()
	go func() {
		raw, _ := ReadFrame(conn)
		var q tabLocationRequest
		json.Unmarshal(raw, &q)
		WriteFrame(conn, map[string]any{"type": "tabLocationResult", "requestId": q.RequestID, "url": "PRIVATE-CANARY"})
	}()
	ctx, cancel := context.WithTimeout(base, 50*time.Millisecond)
	defer cancel()
	r, e = g.MatchTabLocation(ctx, p, handle, c.grant.Origins[0], "")
	if e != nil || r.Available || r.Reason != "transportUnavailable" {
		t.Fatal(r, e)
	}
}
func TestActivateTabUsesExactBrowserAdmissionNoRendererAndConsumesOnce(t *testing.T) {
	g, p, ctx, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.tabMetadataVersion = 1
	c.executorQualified = true
	c.privateFlow = &credentialFlow{}
	g.broker.mu.Unlock()
	handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
	held, epoch, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
	if e != nil || epoch <= 0 {
		t.Fatal(e)
	}
	go func() {
		raw, _ := ReadFrame(conn)
		var q openOriginRequest
		json.Unmarshal(raw, &q)
		if q.Type != "browser.activateTab" || q.TabID != 7 || strings.Contains(string(raw), "identity") {
			return
		}
		WriteFrame(conn, openOriginReply{Type: "browser.activateTabResult", RequestID: q.RequestID, AttemptID: q.AttemptID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, DispatchState: "dispatched", TabID: 7, ErrorCode: "none"})
	}()
	result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, strings.Repeat("a", 64), func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil })
	if e != nil || result.DispatchState != "dispatched" || result.VerificationState != "verified" || result.Value != nil {
		t.Fatal(result, e)
	}
	if _, e = g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, strings.Repeat("a", 64), func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil }); e == nil {
		t.Fatal("replayed activation admission")
	}
}

func TestActivateTabLostReplyAndWrongTargetNeverBecomeConfirmed(t *testing.T) {
	for _, mode := range []string{"lost", "wrongTarget", "staleFence"} {
		t.Run(mode, func(t *testing.T) {
			g, p, base, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.tabMetadataVersion = 1
			c.executorQualified = true
			g.broker.mu.Unlock()
			handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
			ctx, cancel := context.WithTimeout(base, 80*time.Millisecond)
			defer cancel()
			held, _, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "wrongTarget" {
				handle = strings.TrimSuffix(handle, "7") + "8"
			}
			if mode == "staleFence" {
				g.broker.mu.Lock()
				c.epoch = "replacement"
				g.broker.mu.Unlock()
			}
			if mode == "lost" {
				go func() { ReadFrame(conn) }()
			}
			result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, strings.Repeat("c", 64), func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil })
			if e == nil || result.VerificationState == "verified" {
				t.Fatal("unproven activation confirmed")
			}
			want := "notDispatched"
			if mode == "lost" {
				want = "unknown"
			}
			if result.DispatchState != want {
				t.Fatal(result)
			}
			if mode == "lost" {
				g.broker.mu.Lock()
				retained := c.unknown[strings.Repeat("c", 64)]
				g.broker.mu.Unlock()
				if !retained {
					t.Fatal("lost attempt unretained")
				}
			}
		})
	}
}

func TestActivateTabUnknownPreservesOnlyAuthenticatedClosedReason(t *testing.T) {
	for _, code := range []string{"activationUnavailable", "receiptUnavailable", "authorityChanged", "PRIVATE-CANARY"} {
		t.Run(code, func(t *testing.T) {
			g, p, base, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.tabMetadataVersion = 1
			c.executorQualified = true
			g.broker.mu.Unlock()
			ctx, cancel := context.WithTimeout(base, 120*time.Millisecond)
			defer cancel()
			handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
			held, _, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
			if e != nil {
				t.Fatal(e)
			}
			go func() {
				raw, e := ReadFrame(conn)
				if e != nil {
					return
				}
				var q openOriginRequest
				json.Unmarshal(raw, &q)
				WriteFrame(conn, openOriginReply{Type: q.Type + "Result", RequestID: q.RequestID, AttemptID: q.AttemptID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, DispatchState: "unknown", ErrorCode: code})
			}()
			result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, strings.Repeat("a", 64), func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil })
			var diagnostic *model.MechanizeError
			expected := code
			if code == "PRIVATE-CANARY" {
				expected = "tabActivationUnknown"
			}
			if !errors.As(e, &diagnostic) || diagnostic.Code != expected || result.DispatchState != "unknown" || result.VerificationState == "verified" || strings.Contains(e.Error(), "CANARY") {
				t.Fatal("unknown reason lost or untrusted", result, e)
			}
			g.broker.mu.Lock()
			retained := c.unknown[strings.Repeat("a", 64)]
			g.broker.mu.Unlock()
			if !retained {
				t.Fatal("unknown gate cleared")
			}
		})
	}
}
