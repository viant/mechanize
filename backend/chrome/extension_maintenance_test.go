package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
)

func TestExtensionMaintenanceProductionIntentStatusAndNoReplay(t *testing.T) {
	g, p, ctx, c, conn := liveTabInventoryFixture(t, 1, 1)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	g.broker.mu.Lock()
	c.privateFlow = &credentialFlow{}
	c.privacy = &credentialPrivacyState{}
	c.unknown["original-input"] = true
	c.attentionCode = "storedFenceMismatch"
	g.broker.mu.Unlock()
	finished := make(chan error, 1)
	reloads := make(chan int, 1)
	go func() {
		var saved json.RawMessage
		count := 0
		for i := 0; i < 3; i++ {
			raw, e := ReadFrame(conn)
			if e != nil {
				finished <- e
				return
			}
			var request extensionMaintenanceRequest
			if e = json.Unmarshal(raw, &request); e != nil {
				finished <- e
				return
			}
			input, _ := json.Marshal(map[string]any{"request": request, "profile": c.grant.ProfileChannel, "browser": c.grant.BrowserInstance, "saved": saved})
			child := exec.CommandContext(ctx, "node", "testdata/extension_maintenance_wire.cjs")
			child.Stdin = bytes.NewReader(input)
			output, e := child.Output()
			if e != nil {
				finished <- e
				return
			}
			var response struct {
				Reply   json.RawMessage `json:"reply"`
				Saved   json.RawMessage `json:"saved"`
				Reloads int             `json:"reloads"`
			}
			if e = json.Unmarshal(output, &response); e != nil {
				finished <- e
				return
			}
			saved = response.Saved
			count += response.Reloads
			if e = WriteFrame(conn, response.Reply); e != nil {
				finished <- e
				return
			}
		}
		reloads <- count
		finished <- nil
	}()
	started := time.Now()
	first, e := g.ReloadExtension(ctx, p, "owned-session", "original-request", "", "", "0.1.70", func(context.Context) error { return nil })
	t.Logf("production_maintenance_socket_ms=%d", time.Since(started).Milliseconds())
	if e != nil || first.DispatchState != "unknown" || first.Reason != "reloadRequested" || first.AttemptID == "" {
		t.Fatal(first, e)
	}
	status, e := g.ExtensionReloadStatus(ctx, p, "owned-session", "original-request", "", "", "0.1.70")
	if e != nil || status.Outcome != "newBootObserved" || !status.BootChanged || !status.MatchesExpectedVersion || status.DispatchState != "unknown" || status.AttemptID != first.AttemptID {
		t.Fatal(status, e)
	}
	again, e := g.ReloadExtension(ctx, p, "owned-session", "original-request", "", "", "0.1.70", func(context.Context) error { return nil })
	if e != nil || again.AttemptID != first.AttemptID || again.DispatchState != "unknown" {
		t.Fatal(again, e)
	}
	if e = <-finished; e != nil {
		t.Fatal(e)
	}
	if <-reloads != 1 {
		t.Fatal("original reload replayed")
	}
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if !c.unknown["original-input"] || c.privateFlow == nil || c.privacy == nil || c.attentionCode != "storedFenceMismatch" || c.executorQualified {
		t.Fatal("maintenance changed original protection/history")
	}
}

func TestExtensionMaintenanceRefusesActiveWorkForeignActorAndUnsupportedWorker(t *testing.T) {
	for _, mode := range []string{"controller", "foreign", "unsupported", "privateInput", "pending", "lifecycleGuard", "admissionDenied", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			version := 1
			if mode == "unsupported" {
				version = 0
			}
			g, p, ctx, c, conn := liveTabInventoryFixture(t, 1, version)
			admit := func(context.Context) error { return nil }
			if mode == "controller" {
				p.ClientID = "controller:site"
				ctx = auth.WithPrincipal(ctx, p)
			} else if mode == "foreign" {
				p.ClientID = "foreign"
			} else if mode == "admissionDenied" {
				admit = func(context.Context) error { return auth.ErrUnauthorized }
			} else if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			g.broker.mu.Lock()
			if mode == "privateInput" {
				c.privateCredential = &credentialDeliveryPending{}
			}
			if mode == "pending" {
				c.pending["input"] = &pending{}
			}
			if mode == "lifecycleGuard" {
				c.lifecycleGuard = &LifecycleReceiptGuard{}
			}
			g.broker.mu.Unlock()
			bounded, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			out, _ := g.ReloadExtension(bounded, p, "session", "request", "", "", "0.1.70", admit)
			if out.DispatchState != "notDispatched" {
				t.Fatal("denied maintenance became uncertain", out)
			}
			conn.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
			if _, e := ReadFrame(conn); e == nil {
				t.Fatal("denied maintenance reached extension")
			}
		})
	}
}

func TestExtensionMaintenanceLostReplyBlocksOnlyOldConnectionAndDoesNotClearHistory(t *testing.T) {
	g, p, ctx, c, conn := liveTabInventoryFixture(t, 1, 1)
	bounded, cancel := context.WithTimeout(ctx, 70*time.Millisecond)
	defer cancel()
	go func() { ReadFrame(conn) }()
	out, _ := g.ReloadExtension(bounded, p, "session", "request", "", "", "0.1.70", func(context.Context) error { return nil })
	if out.DispatchState != "unknown" || out.Reason != "transportUnavailable" {
		t.Fatal(out)
	}
	if _, e := g.broker.call(ctx, c, Command{Action: "executor.acquire", Identity: Identity{TabID: 7}}, false); e == nil {
		t.Fatal("input crossed uncertain extension reload")
	}
	g.broker.mu.Lock()
	retained := c.extensionMaintenanceBlocked && c.conn != nil && c.extensionMaintenancePending == nil
	g.broker.mu.Unlock()
	if !retained {
		t.Fatal("uncertain original reload lost its connection guard")
	}
	if ExtensionMaintenanceAttemptID(p, "session", "request", "p", "b") == ExtensionMaintenanceAttemptID(p, "other-session", "request", "p", "b") {
		t.Fatal("request not session-bound")
	}
	if ValidExtensionVersion("0.1.70000") || ValidExtensionVersion("PRIVATE_CANARY") {
		t.Fatal("invalid version admitted")
	}
	if strings.Contains(out.Reason, "PRIVATE") {
		t.Fatal("private error escaped")
	}
}
