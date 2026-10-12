package chrome

import (
	"encoding/json"
	"github.com/viant/mechanize/auth"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPrivateControllerOnlyCanonicalOpaqueContinuations(t *testing.T) {
	now := time.Now()
	base := map[string]any{"type": "controllerRequest", "requestId": "request", "operation": "tools/call", "deadlineUnixMs": now.Add(time.Second).UnixMilli(), "origin": "https://controller.test", "documentId": "controller-doc", "sessionId": "approved-port", "brokerEpoch": "broker", "channelEpoch": "channel", "scopeHash": strings.Repeat("a", 64)}
	for _, name := range []string{"mechanize_credential_apply", "mechanize_credential_submit", "mechanize_credential_status", "mechanize_session_close"} {
		args := map[string]any{"sessionId": "runtime-session"}
		if name != "mechanize_session_close" {
			args["preparationId"] = strings.Repeat("a", 64)
		}
		base["params"] = map[string]any{"name": name, "arguments": args}
		raw, _ := json.Marshal(base)
		r := decodePrivateControllerRequest(raw, now)
		if r == nil || !r.privateContinuation || r.privateSession != "runtime-session" {
			t.Fatal("opaque continuation rejected")
		}
		args["value"] = "PRIVATE-CANARY"
		raw, _ = json.Marshal(base)
		if decodePrivateControllerRequest(raw, now) != nil {
			t.Fatal("value-bearing private controller frame accepted")
		}
	}
	for _, name := range []string{"mechanize_credential_prepare", "mechanize_observe", "mechanize_act", "initialize"} {
		base["params"] = map[string]any{"name": name, "arguments": map[string]any{"sessionId": "runtime-session", "preparationId": strings.Repeat("a", 64)}}
		raw, _ := json.Marshal(base)
		if decodePrivateControllerRequest(raw, now) != nil {
			t.Fatal("generic method reopened quarantine")
		}
	}
}
func TestPrivateControllerBindsApprovedConversationToOriginalCredentialSession(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "private-controller", []string{"desktop:control"})
	p.ClientID = "controller:owned"
	a, z := net.Pipe()
	defer a.Close()
	defer z.Close()
	c := &channel{conn: a, privateOwner: p, privateConsent: auth.ConsentBinding{SessionID: "runtime-owned"}, controllerSessions: map[string]*ControllerSession{"port": {identity: ControllerIdentity{Principal: p, ConversationID: "port"}}}}
	b := &Broker{}
	r := &controllerRequest{privateContinuation: true, privateSession: "runtime-owned", SessionID: "port"}
	if !b.privateControllerAllowedLocked(c, a, r) {
		t.Fatal("owned controller denied")
	}
	r.privateSession = "foreign"
	if b.privateControllerAllowedLocked(c, a, r) {
		t.Fatal("foreign runtime borrowed quarantine")
	}
	r.privateSession = "runtime-owned"
	c.privateOwner.ClientID = "different"
	if b.privateControllerAllowedLocked(c, a, r) {
		t.Fatal("foreign controller client borrowed quarantine")
	}
}

func TestPrivateControllerContinuationStillRequiresLiveNativeApproval(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "private-controller", []string{"desktop:observe", "desktop:control"})
	p.ClientID = "controller:owned"
	a, z := net.Pipe()
	defer a.Close()
	defer z.Close()
	now := time.Now()
	s := &ControllerSession{Approved: true, Origin: "https://controller.test", DocumentID: "controller-doc", ExpiresAt: now.Add(time.Minute), identity: ControllerIdentity{Principal: p, ConversationID: "port"}}
	c := &channel{conn: a, scopeQualified: true, profileQualified: true, grant: Enrollment{TrustScope: TrustScopeProfile, Principal: p}, epoch: "channel", scopeHash: strings.Repeat("a", 64), privateInspection: &credentialAdmissionPending{}, privateOwner: p, privateConsent: auth.ConsentBinding{SessionID: "runtime-owned"}, controllerPolicy: ControllerPolicy{Enabled: true, Origins: []string{s.Origin}}, controllerSessions: map[string]*ControllerSession{"port": s}}
	b := &Broker{epoch: "broker"}
	r := &controllerRequest{privateContinuation: true, privateSession: "runtime-owned", SessionID: "port", Origin: s.Origin, DocumentID: s.DocumentID, BrokerEpoch: "broker", ChannelEpoch: c.epoch, ScopeHash: c.scopeHash, Deadline: now.Add(time.Second).UnixMilli()}
	if !b.controllerRequestAllowedLocked(c, a, r) {
		t.Fatal("approved opaque continuation denied")
	}
	s.Approved = false
	if b.controllerRequestAllowedLocked(c, a, r) {
		t.Fatal("native approval bypassed")
	}
	s.Approved = true
	r.privateContinuation = false
	if b.controllerRequestAllowedLocked(c, a, r) {
		t.Fatal("general controller decoder reopened private lane")
	}
}
