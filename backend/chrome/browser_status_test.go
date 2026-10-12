package chrome

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/session"
)

func TestBrowserStatusOwnedMetadataAndAttentionRedaction(t *testing.T) {
	dir := trustScopeTestDirectory(t)
	owner, other := principal(t, "status-owner"), principal(t, "foreign-owner")
	grants := []Enrollment{enrollment(owner, "owned-status"), enrollment(other, "foreign-status")}
	for i := range grants {
		grants[i].TrustScope = TrustScopeDesktop
	}
	credential := strings.Repeat("private-credential", 3)
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/private/process-secret/native-host", StartToken: "1790000000:1"}
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/private/process-secret/Chrome", StartToken: "1790000000:2"}
	var invalid atomic.Bool
	check := func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) {
		return nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: !invalid.Load()}, nil
	}
	credentials := map[string]string{}
	for _, g := range grants {
		credentials[channelKey(g.ProfileChannel, g.BrowserInstance)] = credential
	}
	b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "status.sock"), Grants: grants}, credentials, check)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	g, _ := NewGateway(b, GatewayOptions{})
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	grant := grants[0]
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "workerBuild": 20, "extensionVersion": "0.1.45", "profileChannel": grant.ProfileChannel, "browserInstance": grant.BrowserInstance, "extensionOrigin": grant.ExtensionOrigin, "credential": credential, "trustScope": TrustScopeDesktop})
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"]})
	WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{{Identity: Identity{ProfileChannel: grant.ProfileChannel, BrowserInstance: grant.BrowserInstance, TabID: 7, FrameID: 0, DocumentID: "private-document", Generation: 1}, Origin: grant.Origins[0], Title: "private-page-title"}}})
	c := b.channels[channelKey(grant.ProfileChannel, grant.BrowserInstance)]
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.inventoryComplete })
	ctx := auth.WithPrincipal(context.Background(), owner)
	b.mu.Lock()
	c.pending["private-request"] = &pending{done: make(chan Reply, 1)}
	c.unknown["private-attempt"] = true
	b.mu.Unlock()
	status, err := g.BrowserStatus(ctx, owner)
	if err != nil || !status.Available || len(status.Channels) != 1 {
		t.Fatalf("owned status: %+v %v", status, err)
	}
	s := status.Channels[0]
	if s.WorkerBuild != 20 || s.ExtensionVersion != "0.1.45" {
		t.Fatal("running worker build marker unavailable", s)
	}
	if !s.Connected || !s.ProcessQualified || !s.ScopeQualified || s.ProfileQualified || !s.ExecutorQualified || !s.InventoryComplete || s.DocumentCount != 1 || s.PendingCount != 1 || s.UnknownCount != 1 {
		t.Fatalf("independent channel stages/counts lost: %+v", s)
	}
	encoded, _ := json.Marshal(status)
	for _, private := range []string{"private", "credential", "documentId", "extensionOrigin", "profileChannel", "browserInstance", "https://", "Title", "Evidence"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("status leaked %s: %s", private, encoded)
		}
	}
	foreign, err := g.BrowserStatus(auth.WithPrincipal(context.Background(), other), other)
	if err != nil || len(foreign.Channels) != 1 || foreign.Channels[0].Connected || foreign.Channels[0].DocumentCount != 0 {
		t.Fatalf("foreign namespace saw owner channel: %+v %v", foreign, err)
	}
	if _, err = g.BrowserStatus(context.Background(), owner); err == nil {
		t.Fatal("unauthenticated diagnostic admitted")
	}
	if _, err = g.BrowserStatus(ctx, other); err == nil {
		t.Fatal("principal override diagnostic admitted")
	}
	for _, code := range []string{"websiteScopeMismatch", "lifecycleInhibited", "storedFenceMismatch", "inventoryUnavailable", "inventoryIncomplete", "executorInjectionFailed", "executorBindingFailed", "executorNotQuiescent", "private-code-credential-secret"} {
		WriteFrame(conn, map[string]any{"type": "attention", "error": map[string]any{"code": code, "message": "private-message-credential-secret", "origin": "https://private.example"}, "reconnectPhase": "inspect", "reconnectReason": "restrictedBrowserPage"})
		want := browserAttentionCode(code)
		waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.attentionCode == want })
		result, err := g.BrowserStatus(ctx, owner)
		if err != nil {
			t.Fatal(err)
		}
		row := result.Channels[0]
		if code == "storedFenceMismatch" {
			if row.ReconnectPhase != "inspect" || row.ReconnectReason != "restrictedBrowserPage" {
				t.Fatal("authenticated closed reconnect phase absent")
			}
		} else if row.ReconnectPhase != "" || row.ReconnectReason != "" {
			t.Fatal("unrelated attention retained reconnect detail")
		}
		if row.AttentionCode != want || row.ExecutorQualified || row.InventoryComplete || row.DocumentCount != 0 || row.PendingCount != 1 || row.UnknownCount != 1 {
			t.Fatalf("attention state/reconciliation barriers changed: %+v", row)
		}
		payload, _ := json.Marshal(result)
		if strings.Contains(string(payload), "private") {
			t.Fatalf("attention echoed payload: %s", payload)
		}
	}
	WriteFrame(conn, map[string]any{"type": "attention", "error": map[string]any{"code": "storedFenceMismatch"}, "reconnectPhase": "journal", "reconnectReason": "journalChanged", "reconnectJournal": map[string]any{"reason": "historyLimit", "version": 1, "historyCount": 64, "state": "adopted", "grantRelation": "new"}})
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.reconnectJournal != nil })
	bounded, e := g.BrowserStatus(ctx, owner)
	if e != nil || bounded.Channels[0].ReconnectJournal == nil || bounded.Channels[0].ReconnectJournal.Reason != "historyLimit" {
		t.Fatal("owned authenticated journal metadata unavailable")
	}
	// Fresh failed process diagnostics must report unqualified without closing or sending input.
	WriteFrame(conn, map[string]any{"type": "attention", "error": map[string]any{"code": "storedFenceMismatch", "message": "private-canary"}, "reconnectPhase": "inventory", "reconnectReason": "inventoryChanged", "reconnectInventoryReason": "nonSetupTab", "reconnectRecovery": map[string]int{"missingLiveReceipts": 1, "unknownLiveReceipts": 0, "unavailableExecutors": 2, "privateSources": 0}})
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.reconnectInventoryReason == "nonSetupTab" })
	detailed, e := g.BrowserStatus(ctx, owner)
	if detailed.Channels[0].ReconnectRecovery == nil || detailed.Channels[0].ReconnectRecovery.UnavailableExecutors != 2 {
		t.Fatal("authenticated recovery counts absent")
	}
	if e != nil || detailed.Channels[0].ReconnectInventoryReason != "nonSetupTab" || detailed.Channels[0].PendingCount != 1 || detailed.Channels[0].UnknownCount != 1 {
		t.Fatal("closed inventory detail lost or reconciliation changed", detailed, e)
	}
	invalid.Store(true)
	result, err := g.BrowserStatus(ctx, owner)
	if err != nil || !result.Channels[0].Connected || result.Channels[0].ProcessQualified || result.Channels[0].ScopeQualified || result.Channels[0].ReconnectJournal != nil {
		t.Fatalf("stale process status: %+v %v", result, err)
	}
	b.mu.Lock()
	connected := c.conn != nil
	delete(c.pending, "private-request")
	delete(c.unknown, "private-attempt")
	b.mu.Unlock()
	if !connected {
		t.Fatal("read-only status revoked connection")
	}
	if result.Channels[0].ReconnectInventoryReason != "" {
		t.Fatal("unqualified peer exposed inventory detail")
	}
	if result.Channels[0].ReconnectRecovery != nil {
		t.Fatal("unqualified process exposed recovery counts")
	}
	invalid.Store(false)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"]})
	waitControl(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return c.attentionCode == "" && c.executorQualified })
	result, err = g.BrowserStatus(ctx, owner)
	if result.Channels[0].ReconnectRecovery != nil {
		t.Fatal("confirmed preparation retained stale recovery counts")
	}
	if err != nil || result.Channels[0].AttentionCode != "" || result.Channels[0].ReconnectPhase != "" || result.Channels[0].ReconnectReason != "" || result.Channels[0].ReconnectJournal != nil || !result.Channels[0].ExecutorQualified {
		t.Fatalf("confirmed preparation did not clear attention: %+v %v", result, err)
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, err = ReadFrame(conn); err == nil {
		t.Fatal("status diagnostic sent a browser command")
	}
}

func TestBrowserSetupAttentionCodesRemainActionable(t *testing.T) {
	for _, code := range []string{"websiteScopeMismatch", "lifecycleInhibited"} {
		if got := browserAttentionCode(code); got != code {
			t.Fatalf("setup diagnostic lost: got %q, want %q", got, code)
		}
	}
	if got := browserAttentionCode("https://private.example/secret"); got != "unclassifiedAttention" {
		t.Fatal("unrecognized diagnostic was exposed")
	}
}

func TestReconnectAttentionProjectionExposesOnlyClosedOwnedMetadata(t *testing.T) {
	for _, test := range []struct{ code, wire, phase, reason string }{
		{"storedFenceMismatch", `{"type":"attention","reconnectPhase":"inspect","reconnectReason":"restrictedBrowserPage"}`, "inspect", "restrictedBrowserPage"},
		{"storedFenceMismatch", `{"reconnectPhase":"PRIVATE_CANARY","reconnectReason":"restrictedBrowserPage"}`, "", ""},
		{"storedFenceMismatch", `{"reconnectPhase":"inspect","reconnectReason":"https://private.invalid/SECRET"}`, "", ""},
		{"unknownEffect", `{"reconnectPhase":"inspect","reconnectReason":"restrictedBrowserPage"}`, "", ""},
		{"storedFenceMismatch", `{"reconnectPhase":"inspect","reconnectPhase":"commit","reconnectReason":"none"}`, "", ""},
		{"storedFenceMismatch", `{"reconnectPhase":null,"reconnectReason":"none"}`, "", ""},
		{"storedFenceMismatch", `{"reconnectPhase":[],"reconnectReason":"none"}`, "", ""},
	} {
		phase, reason := closedReconnectAttention([]byte(test.wire), test.code)
		if phase != test.phase || reason != test.reason {
			t.Fatal("unsafe reconnect attention projection")
		}
		raw, _ := json.Marshal(BrowserChannelStatus{ReconnectPhase: phase, ReconnectReason: reason})
		if strings.Contains(string(raw), "PRIVATE") || strings.Contains(string(raw), "SECRET") {
			t.Fatal("private canary escaped")
		}
	}
}

func TestReconnectJournalAttentionContainsOnlyBoundedShape(t *testing.T) {
	for _, reason := range []string{"historyLimit", "bindingSnapshotUnavailable"} {
		raw, _ := json.Marshal(map[string]any{"reconnectPhase": "inventory", "reconnectReason": "journalChanged", "reconnectJournal": map[string]any{"reason": reason, "version": 2, "historyCount": 36, "state": "pending", "grantRelation": "old"}, "private": "PRIVATE_CANARY"})
		got := closedReconnectJournalAttention(raw, "storedFenceMismatch")
		if got == nil || got.Reason != reason {
			t.Fatal("bounded journal failure classification lost", reason)
		}
	}

	valid := map[string]any{"reason": "recoveryDepthLimit", "version": 6, "historyCount": 0, "state": "pending", "grantRelation": "old"}
	frame := func(journal map[string]any, reason string) []byte {
		raw, _ := json.Marshal(map[string]any{"type": "attention", "reconnectPhase": "journal", "reconnectReason": reason, "reconnectJournal": journal})
		return raw
	}
	if got := closedReconnectJournalAttention(frame(valid, "journalChanged"), "storedFenceMismatch"); got == nil || got.Reason != "recoveryDepthLimit" || got.Version != 6 || got.HistoryCount != 0 || got.GrantRelation != "old" {
		t.Fatal("valid bounded journal summary omitted")
	}
	for _, mode := range []string{"unknownReason", "unknownState", "unknownRelation", "negativeCount", "excessCount", "excessVersion", "nullVersion", "extra", "missing"} {
		journal := map[string]any{}
		for key, value := range valid {
			journal[key] = value
		}
		switch mode {
		case "unknownReason":
			journal["reason"] = "PRIVATE_CANARY"
		case "unknownState":
			journal["state"] = "PRIVATE_CANARY"
		case "unknownRelation":
			journal["grantRelation"] = "PRIVATE_CANARY"
		case "negativeCount":
			journal["historyCount"] = -2
		case "excessCount":
			journal["historyCount"] = 65
		case "excessVersion":
			journal["version"] = 7
		case "nullVersion":
			journal["version"] = nil
		case "extra":
			journal["nonce"] = "PRIVATE_CANARY"
		case "missing":
			delete(journal, "state")
		}
		if closedReconnectJournalAttention(frame(journal, "journalChanged"), "storedFenceMismatch") != nil {
			t.Fatalf("accepted malformed journal metadata: %s", mode)
		}
	}
	if closedReconnectJournalAttention(frame(valid, "scopeChanged"), "storedFenceMismatch") != nil || closedReconnectJournalAttention(frame(valid, "journalChanged"), "unknownEffect") != nil {
		t.Fatal("unrelated attention exposed journal detail")
	}
}
