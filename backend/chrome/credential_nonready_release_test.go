package chrome

import (
	"context"
	"encoding/json"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"strings"
	"testing"
	"time"
)

func TestNonReadyInspectionRetirementRestoresControllerCaptureAndTabActivation(t *testing.T) {
	g, _, _, conn, c, doc := credentialAdmissionFixture(t)
	b := g.broker
	dispatched := &controllerDispatchFixture{closed: make(chan struct{}, 1), call: func(ctx context.Context, id ControllerIdentity, call ControllerToolCall) (*schema.CallToolResult, error) {
		if call.Name != "mechanize_capture_windows" {
			t.Error("unexpected tool dispatch")
		}
		return &schema.CallToolResult{StructuredContent: map[string]any{"bundleId": "fixture.app", "windows": []any{}, "returnedAt": time.Now().UTC().Format(time.RFC3339Nano), "truncated": false}}, nil
	}}
	if e := g.SetControllerDispatcher(dispatched); e != nil {
		t.Fatal(e)
	}
	b.mu.Lock()
	c.grant.Principal.Scopes = append(c.grant.Principal.Scopes, "desktop:observe")
	c.tabMetadataVersion = 1
	c.controllerPolicy = ControllerPolicy{Enabled: true, Origins: []string{"https://controller.test"}}
	s := &ControllerSession{ID: "controller-port", Origin: "https://controller.test", DocumentID: "controller-document", Approved: true, ExpiresAt: time.Now().Add(time.Minute)}
	c.controllerSessions = map[string]*ControllerSession{s.ID: s}
	b.initControllerSessionLocked(c, s)
	p := s.identity.Principal
	b.mu.Unlock()
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "runtime-session", GrantID: "grant", Purpose: "login"})
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	responder := make(chan struct{})
	go func() {
		defer close(responder)
		raw, e := ReadFrame(conn)
		if e != nil {
			return
		}
		var req struct {
			RequestID string `json:"requestId"`
		}
		json.Unmarshal(raw, &req)
		WriteFrame(conn, map[string]any{"type": "credentialInspectResult", "privateCredentialProtocolVersion": 2, "requestId": req.RequestID, "identity": doc.Identity, "ready": false, "stage": "unavailable"})
	}()
	admission, e := g.AdmitCredentialControl(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin}, func(context.Context) error { return nil })
	<-responder
	if e == nil || !admission.PreflightNoInput || admission.Created || admission.Confirmed {
		t.Fatal("non-ready inspection lacked trusted no-input proof")
	}
	request := func(id string) {
		if e := WriteFrame(conn, map[string]any{"type": "controllerRequest", "requestId": id, "operation": "tools/call", "deadlineUnixMs": time.Now().Add(2 * time.Second).UnixMilli(), "origin": s.Origin, "documentId": s.DocumentID, "sessionId": s.ID, "brokerEpoch": b.epoch, "channelEpoch": c.epoch, "scopeHash": c.scopeHash, "params": map[string]any{"name": "mechanize_capture_windows", "arguments": map[string]any{"sessionId": "runtime-session", "purpose": "screen review", "surface": map[string]any{"kind": "native", "bundleId": "fixture.app"}, "limit": 8}}}); e != nil {
			t.Fatal(e)
		}
	}
	request("before-retirement")
	raw, e := ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "controllerToolRejected") || dispatched.calls.Load() != 0 {
		t.Fatal("quarantine unexpectedly reopened")
	}
	if _, _, e = g.PrepareActivateTab(ctx, p, doc.Origin, doc.QualifiedTabID()); e == nil {
		t.Fatal("active quarantine allowed activation")
	}
	if e = g.RetireCredentialPreflight(ctx, p, strings.Repeat("b", 64), doc.Origin); e != nil {
		t.Fatal(e)
	}
	b.mu.Lock()
	originalDocs := len(c.documents)
	fake := &pending{command: Command{RequestID: "public-read", Identity: doc.Identity, Action: "read"}, done: make(chan Reply, 1)}
	c.pending["public-read"] = fake
	b.mu.Unlock()
	WriteFrame(conn, map[string]any{"type": "credentialInspectResult", "requestId": "public-read", "identity": doc.Identity, "value": "PRIVATE_CANARY", "ready": false})
	request("after-retirement")
	raw, e = ReadFrame(conn)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "PRIVATE_CANARY") || dispatched.calls.Load() != 1 {
		t.Fatal("capture blocked or private reply escaped")
	}
	select {
	case <-fake.done:
		t.Fatal("late private inspector completed public read")
	default:
	}
	b.mu.Lock()
	delete(c.pending, "public-read")
	retired := c.privateInspection == nil
	docs := len(c.documents)
	b.mu.Unlock()
	if !retired || docs != originalDocs || docs == 0 {
		t.Fatal("no-input retirement lost safe document metadata")
	}
	if _, _, e = g.PrepareActivateTab(ctx, p, doc.Origin, doc.QualifiedTabID()); e != nil {
		t.Fatal("known no-input retirement still blocks tab activation", e)
	}
}

func TestLatePrivateInspectionCannotPoisonNewInspection(t *testing.T) {
	current := &credentialAdmissionPending{requestID: "current", done: make(chan credentialAdmissionReply, 1)}
	c := &channel{privateInspection: current}
	b := &Broker{}
	raw := []byte(`{"type":"credentialInspectResult","requestId":"old","value":"PRIVATE_CANARY"}`)
	if !b.acceptCredentialAdmissionLocked(c, raw) {
		t.Fatal("private reply not quarantined")
	}
	select {
	case <-current.done:
		t.Fatal("old inspector poisoned new correlation")
	default:
	}
	for _, v := range raw {
		if v != 0 {
			t.Fatal("private frame not wiped")
		}
	}
}
