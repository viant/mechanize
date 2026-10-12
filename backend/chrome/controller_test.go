package chrome

import (
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"net"
	"testing"
	"time"
)

func TestControllerClosedRequest(t *testing.T) {
	now := time.Now()
	valid := map[string]any{"type": "controllerRequest", "requestId": "r1", "operation": "connection.status", "deadlineUnixMs": now.Add(time.Second).UnixMilli(), "origin": "http://localhost:3000", "documentId": "d1", "sessionId": "s1", "brokerEpoch": "b", "channelEpoch": "c", "scopeHash": "h"}
	for _, tc := range []struct {
		key   string
		value any
	}{{"origin", "https://*.example.test"}, {"origin", "http://public.example.test"}, {"origin", "https://fixture.example.test/path"}, {"operation", "vault.read"}, {"token", "secret"}, {"deadlineUnixMs", now.Add(time.Minute).UnixMilli()}, {"documentId", ""}} {
		cp := map[string]any{}
		for k, v := range valid {
			cp[k] = v
		}
		cp[tc.key] = tc.value
		raw, _ := json.Marshal(cp)
		if r, handled := decodeControllerRequest(raw, now); !handled || r != nil {
			t.Fatalf("accepted %s=%v", tc.key, tc.value)
		}
	}
	for _, origin := range []string{"http://localhost:3000", "https://steward.agently.viantinc.com"} {
		valid["origin"] = origin
		raw, _ := json.Marshal(valid)
		if r, ok := decodeControllerRequest(raw, now); !ok || r == nil {
			t.Fatal("rejected exact origin")
		}
	}
}
func TestControllerPrincipalAndChannelBinding(t *testing.T) {
	b := &Broker{epoch: "b"}
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	c := &channel{conn: conn, epoch: "c", scopeHash: "h", profileQualified: true, scopeQualified: true, executorQualified: true, grant: Enrollment{TrustScope: TrustScopeProfile, Principal: auth.Principal{Scopes: []string{"desktop:observe"}}}}
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://fixture.example.test"}}
	c.controllerSessions = map[string]*ControllerSession{"s1": {Approved: true, Origin: "https://fixture.example.test", DocumentID: "d1", ExpiresAt: time.Now().Add(time.Minute)}}
	r := &controllerRequest{Operation: "connection.status", Origin: "https://fixture.example.test", DocumentID: "d1", SessionID: "s1", RequestID: "r", BrokerEpoch: "b", ChannelEpoch: "c", ScopeHash: "h", Deadline: time.Now().Add(time.Second).UnixMilli()}
	if got := b.controllerReply(c, conn, r); got["ready"] != true {
		t.Fatal(got)
	}
	r.ChannelEpoch = "stale"
	if got := b.controllerReply(c, conn, r); got["error"] != "unavailable" {
		t.Fatal(got)
	}
	r.ChannelEpoch = "c"
	c.grant.Principal.Scopes = nil
	if got := b.controllerReply(c, conn, r); got["error"] != "unavailable" {
		t.Fatal(got)
	}
}

func TestControllerRoundTripOverAuthenticatedBrokerChannel(t *testing.T) {
	g := enrollment(principal(t, "controller-fixture"), "controller-channel")
	b := fixtureBroker(t, g)
	conn := connectHost(t, b, g)
	b.mu.Lock()
	c := b.channels[channelKey(g.ProfileChannel, g.BrowserInstance)]
	r := controllerRequest{Type: "controllerRequest", RequestID: "r1", Operation: "connection.status", Deadline: time.Now().Add(time.Second).UnixMilli(), Origin: "http://localhost:3000", DocumentID: "d1", SessionID: "s1", BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash}
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{r.Origin}}
	c.controllerSessions = map[string]*ControllerSession{"s1": {Approved: true, Origin: r.Origin, DocumentID: r.DocumentID, ExpiresAt: time.Now().Add(time.Minute)}}
	b.mu.Unlock()
	if err := WriteFrame(conn, r); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	raw, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result["type"] != "controllerResult" || result["requestId"] != "r1" || result["ready"] != false || len(result) != 3 {
		t.Fatalf("unexpected projected result %s", raw)
	}
	// Replayed IDs terminate the channel rather than executing again.
	if err := WriteFrame(conn, r); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadFrame(conn); err == nil {
		t.Fatal("accepted replay")
	}
}

func TestControllerProcessScopeRemainsRequiredWithoutExecutor(t *testing.T) {
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	b := &Broker{epoch: "broker"}
	c := &channel{conn: conn, scopeQualified: true, profileQualified: true, epoch: "channel", scopeHash: "scope", grant: Enrollment{TrustScope: TrustScopeProfile, Principal: auth.Principal{Scopes: []string{"desktop:observe"}}}, controllerPolicy: ControllerPolicy{Enabled: true, Origins: []string{"https://controller.test"}}, controllerSessions: map[string]*ControllerSession{"session": {Approved: true, Origin: "https://controller.test", DocumentID: "document", ExpiresAt: time.Now().Add(time.Minute)}}}
	r := &controllerRequest{Operation: "connection.status", SessionID: "session", Origin: "https://controller.test", DocumentID: "document", BrokerEpoch: b.epoch, ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: time.Now().Add(time.Second).UnixMilli()}
	if got := b.controllerReply(c, conn, r); got["ready"] != false || got["error"] != nil {
		t.Fatal("process-qualified connection without executor was not truthfully reported", got)
	}
	r.Operation = "browser.inventory.summary"
	if got := b.controllerReply(c, conn, r); got["error"] != "unavailable" || got["documentCount"] != nil {
		t.Fatal("unqualified inventory was presented as empty", got)
	}
	for _, scenario := range []string{"scope", "profile", "process", "private", "lifecycle", "disconnected"} {
		t.Run(scenario, func(t *testing.T) {
			copy := *c
			switch scenario {
			case "scope":
				copy.scopeQualified = false
			case "profile":
				copy.profileQualified = false
			case "process":
				copy.grant.TrustScope = TrustScopeDesktop
				copy.profileQualified = false
			case "private":
				copy.privateInspection = &credentialAdmissionPending{}
			case "lifecycle":
				copy.lifecycleInhibited = true
			case "disconnected":
				copy.conn = nil
			}
			if b.controllerRequestAllowedLocked(&copy, conn, r) {
				t.Fatal("controller bypassed", scenario)
			}
		})
	}
}
