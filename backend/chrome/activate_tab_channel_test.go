package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth/nativepeer"
)

func TestActivateTabUnqualifiedDocumentChannelDispatchesOnceWithoutRenderer(t *testing.T) {
	g, p, ctx, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.tabMetadataVersion = 1
	c.openOriginVersion = 1
	// Retained dormant private-source metadata is not page-input authority.
	c.privateFlow = &credentialFlow{}
	g.broker.mu.Unlock()
	if c.executorQualified || c.inventoryComplete || len(c.documents) != 0 {
		t.Fatal("fixture unexpectedly qualified a renderer")
	}
	caps := scopedCapabilityMap(t, g, ctx, p)
	if !caps["web:browser.activateTab"] || caps["web:browser.openOrigin"] || caps["web:element.press"] || caps["web:observe"] {
		t.Fatal("browser visibility changed renderer/open-origin capabilities")
	}
	if _, _, e := g.PrepareOpenOrigin(ctx, p, c.grant.Origins[0]); e == nil {
		t.Fatal("unqualified openOrigin admitted")
	}
	handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
	held, epoch, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
	if e != nil || epoch <= 0 {
		t.Fatal(e)
	}
	var commits atomic.Int32
	workerDone := make(chan error, 1)
	go func() {
		raw, e := ReadFrame(conn)
		if e != nil {
			workerDone <- e
			return
		}
		var q openOriginRequest
		if json.Unmarshal(raw, &q) != nil || q.Type != "browser.activateTab" || q.TabID != 7 || q.Origin != c.grant.Origins[0] || strings.Contains(string(raw), "identity") || commits.Load() != 1 {
			workerDone <- errors.New("unexpected or uncommitted browser command")
			return
		}
		workerDone <- WriteFrame(conn, openOriginReply{Type: "browser.activateTabResult", RequestID: q.RequestID, AttemptID: q.AttemptID, BrokerEpoch: q.BrokerEpoch, ChannelEpoch: q.ChannelEpoch, ScopeHash: q.ScopeHash, DispatchState: "dispatched", TabID: 7, ErrorCode: "none"})
	}()
	attempt := strings.Repeat("c", 64)
	result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, attempt, func(context.Context) error { return nil }, func(_ context.Context, b ActivationBinding) error {
		if b.ClientID != p.ClientID || b.TabID != 7 || b.BrowserAttemptID != attempt || b.ChromePID != 10 || b.NativeHostPID != 20 || b.BrokerEpoch != g.broker.epoch || b.ChannelEpoch != c.epoch || b.ScopeHash != c.scopeHash {
			return errors.New("activation binding lost original authority")
		}
		commits.Add(1)
		return nil
	})
	if e != nil || result.DispatchState != "dispatched" || result.VerificationState != "verified" || result.Value != nil {
		t.Fatal(result, e)
	}
	if e = <-workerDone; e != nil {
		t.Fatal(e)
	}
	if _, e = g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, attempt, func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil }); e == nil {
		t.Fatal("activation admission replayed")
	}
	conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, e = ReadFrame(conn); e == nil {
		t.Fatal("replay or renderer command reached socket")
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if commits.Load() != 1 || c.executorQualified || c.inventoryComplete || len(c.documents) != 0 || c.privateFlow == nil || len(c.pending) != 0 || c.openOriginPending != nil {
		t.Fatal("tab activation changed renderer/private authority")
	}
}

func TestActivateTabUnqualifiedChannelPreservesIdleGuards(t *testing.T) {
	guards := map[string]func(*channel){
		"scope":             func(c *channel) { c.scopeQualified = false },
		"fixture":           func(c *channel) { c.fixtureOnly = true },
		"controlScope":      func(c *channel) { c.grant.Principal.Scopes = []string{"desktop:observe"} },
		"lifecycle":         func(c *channel) { c.lifecycleInhibited = true },
		"lifecycleGuard":    func(c *channel) { c.lifecycleGuard = &LifecycleReceiptGuard{} },
		"unknown":           func(c *channel) { c.unknown["original-unknown"] = true },
		"pendingInput":      func(c *channel) { c.pending["original-pending"] = &pending{} },
		"playwright":        func(c *channel) { c.playwright = &playwrightExecution{} },
		"privateInspection": func(c *channel) { c.privateInspection = &credentialAdmissionPending{} },
		"privateDelivery":   func(c *channel) { c.privateCredential = &credentialDeliveryPending{} },
		"privateAdvance":    func(c *channel) { c.privateAdvance = &credentialAdvancePending{} },
		"privacyPending":    func(c *channel) { c.privacyPending = &credentialPrivacyPending{} },
		"manualPending":     func(c *channel) { c.manualPending = &manualCredentialPending{} },
		"browserPending":    func(c *channel) { c.openOriginPending = &openOriginPending{} },
	}
	for name, guard := range guards {
		for _, stage := range []string{"prepare", "dispatch"} {
			t.Run(name+"/"+stage, func(t *testing.T) {
				g, p, ctx, c, conn := setupFixture(t)
				g.broker.mu.Lock()
				c.tabMetadataVersion = 1
				g.broker.mu.Unlock()
				handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
				held := ctx
				if stage == "dispatch" {
					var e error
					held, _, e = g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
					if e != nil {
						t.Fatal(e)
					}
				}
				g.broker.mu.Lock()
				guard(c)
				g.broker.mu.Unlock()
				if stage == "prepare" {
					if _, _, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle); e == nil {
						t.Fatal("busy channel prepared")
					}
					if scopedCapabilityMap(t, g, ctx, p)["web:browser.activateTab"] {
						t.Fatal("busy activation advertised")
					}
				} else {
					result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, strings.Repeat("a", 64), func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error {
						t.Error("binding committed despite busy channel")
						return nil
					})
					if e == nil || result.DispatchState != "notDispatched" {
						t.Fatal(result, e)
					}
				}
				conn.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
				if _, e := ReadFrame(conn); e == nil {
					t.Fatal("busy channel reached browser")
				}
			})
		}
	}
}

func TestActivateTabUnqualifiedChannelRequiresCurrentActorProcessAndOrigin(t *testing.T) {
	for _, mode := range []string{"foreignClient", "origin", "processChanged", "cancelled", "staleFence"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, c, conn := setupFixture(t)
			g.broker.mu.Lock()
			c.tabMetadataVersion = 1
			g.broker.mu.Unlock()
			handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
			origin := c.grant.Origins[0]
			if mode == "foreignClient" {
				p.ClientID = "foreign"
			} else if mode == "origin" {
				origin = "https://foreign.test"
			} else if mode == "processChanged" {
				g.broker.verifyPeer = func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
					return nativepeer.ChromeProcessEvidence{}, errors.New("changed peer")
				}
			} else if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mode != "staleFence" {
				if _, _, e := g.PrepareActivateTab(ctx, p, origin, handle); e == nil {
					t.Fatal("unowned/stale activation admitted")
				}
			} else {
				held, _, e := g.PrepareActivateTab(ctx, p, origin, handle)
				if e != nil {
					t.Fatal(e)
				}
				g.broker.mu.Lock()
				c.epoch = "replacement"
				g.broker.mu.Unlock()
				result, e := g.ExecuteActivateTabBound(held, p, origin, handle, strings.Repeat("b", 64), func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil })
				if e == nil || result.DispatchState != "notDispatched" {
					t.Fatal(result, e)
				}
			}
			conn.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
			if _, e := ReadFrame(conn); e == nil {
				t.Fatal("unowned/stale activation reached browser")
			}
		})
	}
}

func TestActivateTabUnqualifiedChannelLostReplyRetainsUnknownWithoutReplay(t *testing.T) {
	g, p, base, c, conn := setupFixture(t)
	g.broker.mu.Lock()
	c.tabMetadataVersion = 1
	g.broker.mu.Unlock()
	handle := (Document{Identity: Identity{ProfileChannel: c.grant.ProfileChannel, BrowserInstance: c.grant.BrowserInstance, TabID: 7}}).QualifiedTabID()
	ctx, cancel := context.WithTimeout(base, 70*time.Millisecond)
	defer cancel()
	held, _, e := g.PrepareActivateTab(ctx, p, c.grant.Origins[0], handle)
	if e != nil {
		t.Fatal(e)
	}
	received := make(chan error, 1)
	go func() { _, e := ReadFrame(conn); received <- e }()
	attempt := strings.Repeat("d", 64)
	result, e := g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, attempt, func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil })
	if e == nil || result.DispatchState != "unknown" || result.VerificationState == "verified" {
		t.Fatal(result, e)
	}
	if e = <-received; e != nil {
		t.Fatal(e)
	}
	if _, _, e = g.PrepareActivateTab(base, p, c.grant.Origins[0], handle); e == nil {
		t.Fatal("UNKNOWN input lane admitted another activation")
	}
	if _, e = g.ExecuteActivateTabBound(held, p, c.grant.Origins[0], handle, attempt, func(context.Context) error { return nil }, func(context.Context, ActivationBinding) error { return nil }); e == nil {
		t.Fatal("lost activation replayed")
	}
	g.broker.mu.Lock()
	retained := c.unknown[attempt] && c.visibilityUnknown[attempt] != nil
	g.broker.mu.Unlock()
	if !retained {
		t.Fatal("original UNKNOWN evidence dropped")
	}
	conn.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
	if _, e = ReadFrame(conn); e == nil {
		t.Fatal("UNKNOWN activation replay reached browser")
	}
}
