package chrome

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

func credentialFreshFixture(t *testing.T, mode string) (*Gateway, auth.Principal, context.Context, ControlAuthority, vault.Binding, *atomic.Int32) {
	t.Helper()
	g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
	calls := &atomic.Int32{}
	pinned := strings.HasPrefix(mode, "pinned")
	if pinned {
		g.broker.mu.Lock()
		c.workerBuild = 22
		g.broker.mu.Unlock()
	}
	go func() {
		for {
			raw, err := ReadFrame(conn)
			if err != nil {
				return
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(raw, &m) != nil {
				return
			}
			var kind, action, request string
			var id Identity
			var lease Lease
			json.Unmarshal(m["type"], &kind)
			json.Unmarshal(m["action"], &action)
			json.Unmarshal(m["requestId"], &request)
			json.Unmarshal(m["identity"], &id)
			if kind == "credentialInspect" {
				fresh := m["controlLease"] != nil
				if fresh {
					calls.Add(1)
					json.Unmarshal(m["controlLease"], &lease)
					expectedFields := 9
					if pinned {
						expectedFields = 10
					}
					if len(m) != expectedFields || lease.ID == "" {
						conn.Close()
						return
					}
				}
				reply := map[string]any{"type": "credentialInspectResult", "privateCredentialProtocolVersion": 2, "stage": "pair", "requestId": request, "identity": id, "ready": true}
				if pinned {
					var recipient string
					json.Unmarshal(m["recipientId"], &recipient)
					reply["recipientId"] = recipient
					reply["privateCredentialProtocolVersion"] = 3
					if fresh {
						id.Generation++
						reply["identity"] = id
					}
				}
				if fresh {
					switch mode {
					case "pinnedWrongNonce":
						reply["recipientId"] = strings.Repeat("e", 64)
					case "pinnedFormAbsent":
						reply["ready"] = false
					case "pinnedEcho":
						reply["value"] = "PRIVATE-CANARY"
					case "pinnedOrigin":
						g.broker.mu.Lock()
						c.documents[0].Origin = "https://changed.invalid"
						g.broker.mu.Unlock()
					case "generation":
						id.Generation++
						reply["identity"] = id
					case "formAbsent":
						reply["ready"] = false
					case "echo":
						reply["value"] = "PRIVATE-CANARY"
					case "latePrevious":
						reply["requestId"] = "old-inspector"
					case "public":
						reply = map[string]any{"type": "documents", "documents": []any{map[string]any{"title": "PRIVATE-CANARY"}}}
					case "disconnect":
						conn.Close()
						return
					case "origin":
						g.broker.mu.Lock()
						c.documents[0].Origin = "https://changed.invalid"
						g.broker.mu.Unlock()
					case "retired":
						g.controlMu.Lock()
						testMarkControlRetiring(g)
						g.controlMu.Unlock()
					}
				}
				if WriteFrame(conn, reply) != nil {
					return
				}
			} else if action == "executor.acquire" {
				json.Unmarshal(m["controlLease"], &lease)
				if WriteFrame(conn, map[string]any{"requestId": request, "identity": id, "validated": true, "controlLease": lease}) != nil {
					return
				}
			} else {
				conn.Close()
				return
			}
		}
	}()
	admitted, err := g.AdmitCredentialControl(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin}, func(context.Context) error { return nil })
	if err != nil || !admitted.Confirmed {
		t.Fatal("fixture admission unavailable", err)
	}
	a := admitted.Authority
	binding := vault.Binding{SessionID: "session", DocumentID: a.Document.DocumentID, NavigationID: CredentialNavigationID(a), Target: vault.Target{Origin: a.Document.Origin, Account: "fixture-account"}}
	return g, p, ctx, a, binding, calls
}
func TestFreshCredentialBindingReusesInspectorAndExactLease(t *testing.T) {
	g, p, ctx, a, binding, calls := credentialFreshFixture(t, "ready")
	for i := 0; i < 2; i++ {
		actual, err := g.FreshCredentialBinding(ctx, p, a, binding, func(context.Context) error { return nil })
		if err != nil || actual != binding {
			t.Fatal("same recipient freshness unavailable", err)
		}
		if g.VerifyControl(ctx, p, a) != nil {
			t.Fatal("freshness replaced retained lease")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("freshness did not make exactly one metadata probe per call")
	}
	c := g.controlChannel(a)
	g.broker.mu.Lock()
	defer g.broker.mu.Unlock()
	if c.privateInspection == nil || c.privateCredential != nil || c.documents[0] != a.Document {
		t.Fatal("freshness changed document or unarmed private demux")
	}
}
func TestFreshCredentialBindingRejectsChangedOrUntrustedRepliesWithoutAdoption(t *testing.T) {
	for _, mode := range []string{"generation", "formAbsent", "echo", "latePrevious", "public", "disconnect", "origin", "retired"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, a, binding, calls := credentialFreshFixture(t, mode)
			actual, err := g.FreshCredentialBinding(ctx, p, a, binding, func(context.Context) error { return nil })
			if err != errCredentialDelivery || actual != (vault.Binding{}) || calls.Load() != 1 {
				t.Fatal("invalid freshness accepted", err)
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatal("private error escaped")
			}
			g.controlMu.Lock()
			retained := testFirstControl(g)
			g.controlMu.Unlock()
			if retained == nil || !sameControl(*retained, a) {
				t.Fatal("freshness adopted a replacement authority")
			}
		})
	}
}
func TestFreshCredentialBindingRejectsUnboundActorConsentAndNavigationBeforeWrite(t *testing.T) {
	for _, mode := range []string{"actor", "consent", "navigation", "document", "origin", "lease", "cancel", "nil", "denied", "panic"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, a, binding, calls := credentialFreshFixture(t, "ready")
			admit := func(context.Context) error { return nil }
			switch mode {
			case "actor":
				other := p
				other.ClientID = "other"
				ctx = auth.WithPrincipal(ctx, other)
			case "consent":
				ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{GrantID: "grant", SessionID: "other", Purpose: "login"})
			case "navigation":
				binding.NavigationID = "unbound"
			case "document":
				binding.DocumentID = "other"
			case "origin":
				binding.Target.Origin = "https://other.invalid"
			case "lease":
				a.Lease.Generation++
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil":
				admit = nil
			case "denied":
				admit = func(context.Context) error { return errors.New("PRIVATE-CANARY") }
			case "panic":
				admit = func(context.Context) error { panic("PRIVATE-CANARY") }
			}
			actual, err := g.FreshCredentialBinding(ctx, p, a, binding, admit)
			if err != errCredentialDelivery || actual != (vault.Binding{}) || calls.Load() != 0 {
				t.Fatal("unbound freshness sent a probe", err)
			}
		})
	}
}
func TestCredentialNavigationIDBindsAllRecipientFences(t *testing.T) {
	g, p, ctx, a, binding, _ := credentialFreshFixture(t, "ready")
	_ = g
	_ = p
	_ = ctx
	for _, mutate := range []func(*ControlAuthority){func(v *ControlAuthority) { v.Document.Generation++ }, func(v *ControlAuthority) { v.ChannelEpoch += "x" }, func(v *ControlAuthority) { v.BrokerEpoch += "x" }, func(v *ControlAuthority) { v.ScopeHash += "x" }, func(v *ControlAuthority) { v.Lease.ID += "x" }, func(v *ControlAuthority) { v.Owner += "x" }, func(v *ControlAuthority) { v.ClientID += "x" }, func(v *ControlAuthority) { v.Document.Origin = "https://other.invalid" }} {
		copy := a
		mutate(&copy)
		if CredentialNavigationID(copy) == binding.NavigationID {
			t.Fatal("recipient fence omitted")
		}
	}
}

func TestPinnedCredentialBindingAcceptsOnlyOriginalRecipientWithFreshDocumentMetadata(t *testing.T) {
	for _, mode := range []string{"pinnedGeneration", "pinnedWrongNonce", "pinnedFormAbsent", "pinnedEcho", "pinnedOrigin"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, a, binding, calls := credentialFreshFixture(t, mode)
			if !fingerprintV2Hash.MatchString(a.PrivateRecipientID) {
				t.Fatal("private recipient was not pinned")
			}
			actual, err := g.FreshCredentialBinding(ctx, p, a, binding, func(context.Context) error { return nil })
			if mode == "pinnedGeneration" {
				if err != nil || actual != binding {
					t.Fatal("same private recipient rejected decoration drift", err)
				}
				if g.VerifyControl(ctx, p, a) != nil {
					t.Fatal("fresh read changed held control authority")
				}
			} else if err == nil || actual.DocumentID != "" {
				t.Fatal("untrusted recipient accepted", mode)
			}
			if calls.Load() != 1 {
				t.Fatal("private probe retried or skipped")
			}
		})
	}
}

func TestPrivateRecipientNavigationIDPreservesLegacyAndBindsNonce(t *testing.T) {
	a := ControlAuthority{Owner: "owner", ClientID: "client", BrokerEpoch: "broker", ChannelEpoch: "channel", ScopeHash: "scope", Document: Document{Identity: Identity{DocumentID: "doc", Generation: 1}, Origin: "https://fixture.test"}, Lease: Lease{ID: "lease", Generation: 1}}
	old, _ := json.Marshal(struct {
		Version                                       string
		Broker, Channel, Scope, Owner, Client, Origin string
		Identity                                      Identity
		Lease                                         Lease
	}{"mechanize-credential-recipient-v1", a.BrokerEpoch, a.ChannelEpoch, a.ScopeHash, a.Owner, a.ClientID, a.Document.Origin, a.Document.Identity, a.Lease})
	hash := sha256.Sum256(old)
	if CredentialNavigationID(a) != hex.EncodeToString(hash[:]) {
		t.Fatal("legacy credential binding changed")
	}
	legacy := CredentialNavigationID(a)
	a.PrivateRecipientID = strings.Repeat("a", 64)
	first := CredentialNavigationID(a)
	a.PrivateRecipientID = strings.Repeat("b", 64)
	if first == legacy || first == CredentialNavigationID(a) {
		t.Fatal("private recipient nonce omitted from binding")
	}
}
