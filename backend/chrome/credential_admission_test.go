package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
)

func credentialAdmissionFixture(t *testing.T) (*Gateway, auth.Principal, context.Context, net.Conn, *channel, Document) {
	t.Helper()
	dir, err := os.MkdirTemp("/private/tmp", "credential-admission-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "local-client"
	ctx := auth.WithPrincipal(context.Background(), p)
	ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "login"})
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	t.Cleanup(cancel)
	parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/fixture/chrome", StartToken: "parent"}
	host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/host", StartToken: "host"}
	evidence := nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}
	grant := Enrollment{Principal: p, ProfileChannel: "profile", BrowserInstance: "browser", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://bank.invalid"}, ProfileDirectory: dir}
	b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("profile", "browser"): strings.Repeat("x", 64)}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return evidence, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	conn, err := net.Dial("unix", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	WriteFrame(conn, map[string]any{"type": "hello", "protocolVersion": 1, "profileChannel": "profile", "browserInstance": "browser", "extensionOrigin": grant.ExtensionOrigin, "credential": strings.Repeat("x", 64), "profileDirectory": dir, "profileLaunchQualified": true})
	raw, _ := ReadFrame(conn)
	var ack map[string]any
	json.Unmarshal(raw, &ack)
	WriteFrame(conn, map[string]any{"type": "executorPrepared", "executorChallenge": ack["executorChallenge"]})
	doc := Document{Identity: credentialTestPending().identity, Origin: "https://bank.invalid"}
	WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{doc}})
	waitControl(t, func() bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.channels[channelKey("profile", "browser")].inventoryComplete
	})
	g, _ := NewGateway(b, GatewayOptions{})
	return g, p, ctx, conn, b.channels[channelKey("profile", "browser")], doc
}
func TestCredentialAdmissionMetadataOnlyAndRetainedLease(t *testing.T) {
	for _, mode := range []string{"ready", "lateInventory", "notReady", "inspectEcho", "acquireEcho", "originDrift", "denied", "unknown", "panic", "missing", "existing", "quarantined"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
			b := g.broker
			if mode == "quarantined" {
				candidate := credentialCandidate{Identity: doc.Identity, Origin: doc.Origin}
				if !candidate.valid(c.grant) {
					t.Fatal("fixture candidate invalid")
				}
				WriteFrame(conn, map[string]any{"type": "documents", "documents": []Document{}, "credentialCandidates": []credentialCandidate{candidate}})
				waitControl(t, func() bool {
					b.mu.Lock()
					defer b.mu.Unlock()
					return len(c.documents) == 0 && len(c.credentialCandidates) == 1
				})
				if _, _, e := b.selectDocument(p, model.Surface{Kind: "web", Origin: doc.Origin}); e == nil {
					t.Fatal("private candidate entered public selection")
				}
			}
			if mode == "unknown" {
				b.mu.Lock()
				c.unknown["original"] = true
				b.mu.Unlock()
			}
			if mode == "existing" {
				old, _, e := g.controlSnapshot(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin})
				if e != nil {
					t.Fatal(e)
				}
				old.Lease = Lease{ID: "old-lease", Generation: 1}
				g.setControlLocked(old)
			}
			requests := make(chan string, 4)
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
					var requestID, kind, action string
					json.Unmarshal(m["requestId"], &requestID)
					if len(requestID) != 64 || strings.Trim(requestID, "0123456789abcdef") != "" {
						t.Error("private wire request ID violates Chrome credential protocol")
					}
					json.Unmarshal(m["type"], &kind)
					json.Unmarshal(m["action"], &action)
					if kind == "credentialInspect" {
						requests <- kind
						if mode == "lateInventory" {
							// An asynchronous inventory started before quarantine may
							// already be queued ahead of the private response.
							WriteFrame(conn, map[string]any{"type": "documents", "documents": []map[string]any{{"title": "private-secret-canary"}}})
						}
						if mode == "missing" {
							conn.Close()
							return
						}
						id := doc.Identity
						id.Generation = 2
						reply := map[string]any{"type": "credentialInspectResult", "privateCredentialProtocolVersion": 2, "stage": "pair", "requestId": requestID, "identity": id, "ready": mode != "notReady"}
						if mode == "inspectEcho" {
							reply["value"] = "private-secret-canary"
						}
						if mode == "originDrift" {
							b.mu.Lock()
							c.documents[0].Origin = "https://other.invalid"
							b.mu.Unlock()
						}
						WriteFrame(conn, reply)
					} else if action == "executor.acquire" {
						requests <- action
						var id Identity
						var lease Lease
						json.Unmarshal(m["identity"], &id)
						json.Unmarshal(m["controlLease"], &lease)
						reply := map[string]any{"requestId": requestID, "identity": id, "validated": true, "controlLease": lease}
						if mode == "acquireEcho" {
							reply["value"] = "private-secret-canary"
						}
						WriteFrame(conn, reply)
					} else {
						requests <- "unexpected"
						return
					}
				}
			}()
			admission, err := g.AdmitCredentialControl(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin}, func(context.Context) error {
				if mode == "denied" {
					return errors.New("private-secret-canary")
				}
				if mode == "panic" {
					panic("private-secret-canary")
				}
				return nil
			})
			if strings.Contains(fmt.Sprintf("%v", err), "canary") {
				t.Fatal("private error escaped")
			}
			if mode == "ready" || mode == "quarantined" || mode == "lateInventory" {
				if err != nil || !admission.Created || !admission.Confirmed || admission.Authority.Document.Generation != 2 || g.VerifyControl(ctx, p, admission.Authority) != nil {
					t.Fatal("fresh secure admission failed")
				}
				if <-requests != "credentialInspect" || <-requests != "executor.acquire" {
					t.Fatal("public Observe or unexpected order")
				}
				b.mu.Lock()
				if c.privateInspection == nil {
					t.Fatal("delayed echo guard removed")
				}
				b.mu.Unlock()
				WriteFrame(conn, map[string]any{"type": "documents", "documents": []map[string]any{{"title": "private-secret-canary"}}})
			} else if err == nil || admission.Confirmed {
				t.Fatal("unsafe admission accepted")
			}
			if mode == "existing" {
				g.controlMu.Lock()
				old := testFirstControl(g)
				g.controlMu.Unlock()
				if old == nil || old.Lease.ID != "old-lease" || old.Document.Generation != 1 {
					t.Fatal("existing authority replaced")
				}
			}
			if mode == "acquireEcho" {
				g.controlMu.Lock()
				retained := testFirstControl(g) != nil
				g.controlMu.Unlock()
				if !admission.Created || !retained {
					t.Fatal("uncertain acquisition erased lease")
				}
			}
			if mode == "denied" || mode == "unknown" || mode == "panic" {
				select {
				case <-requests:
					t.Fatal("refused gate performed probe")
				default:
				}
			}
			b.mu.Lock()
			for _, d := range c.documents {
				if strings.Contains(d.Title, "canary") {
					t.Fatal("private echo became document")
				}
			}
			if mode == "unknown" && !c.unknown["original"] {
				t.Fatal("old unknown erased")
			}
			if len(c.attempts) != 0 || len(c.receipts) != 0 {
				t.Fatal("admission entered command journal")
			}
			b.mu.Unlock()
		})
	}
}

func TestPinnedInspectorReplyRequiresExactNonceProtocolAndClosedIdentity(t *testing.T) {
	source := credentialTestPending()
	p := &credentialAdmissionPending{requestID: source.requestID, identity: source.identity}
	p.recipientID = strings.Repeat("f", 64)
	base := map[string]any{"type": "credentialInspectResult", "requestId": p.requestID, "identity": p.identity, "ready": true, "stage": "pair", "privateCredentialProtocolVersion": 3, "recipientId": p.recipientID}
	for _, mode := range []string{"valid", "advancedGeneration", "wrongNonce", "downgrade", "missingNonce", "extraValue", "foreignDocument"} {
		t.Run(mode, func(t *testing.T) {
			r := map[string]any{}
			for k, v := range base {
				r[k] = v
			}
			if mode == "advancedGeneration" {
				id := p.identity
				id.Generation++
				r["identity"] = id
			}
			if mode == "wrongNonce" {
				r["recipientId"] = strings.Repeat("e", 64)
			}
			if mode == "downgrade" {
				r["privateCredentialProtocolVersion"] = 2
			}
			if mode == "missingNonce" {
				delete(r, "recipientId")
			}
			if mode == "extraValue" {
				r["value"] = "PASSWORD-CANARY"
			}
			if mode == "foreignDocument" {
				id := p.identity
				id.DocumentID = "foreign"
				r["identity"] = id
			}
			raw, _ := json.Marshal(r)
			result := decodeCredentialAdmission(raw, p)
			valid := mode == "valid" || mode == "advancedGeneration"
			if result.ready != valid {
				t.Fatal("private inspector reply accepted incorrectly", mode)
			}
			if !valid && result.recipientID != "" {
				t.Fatal("invalid private recipient retained")
			}
		})
	}
}
func TestNegotiatedInspectionReasonIsClosedAndCorrelated(t *testing.T) {
	identity := Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, FrameID: 0, DocumentID: "doc", Generation: 1}
	pending := &credentialAdmissionPending{requestID: strings.Repeat("a", 64), identity: identity, recipientID: strings.Repeat("b", 64), diagnostics: true}
	for _, reason := range []string{"fieldsUnavailable", "submitterUnavailable", "challenge", "documentBindingUnavailable", "privateInputRetained"} {
		stage := "unavailable"
		if reason == "challenge" {
			stage = "challenge"
		}
		frame := map[string]any{"type": "credentialInspectResult", "requestId": pending.requestID, "identity": identity, "ready": false, "stage": stage, "privateCredentialProtocolVersion": 3, "recipientId": pending.recipientID, "inspectionReason": reason}
		raw, _ := json.Marshal(frame)
		reply := decodeCredentialAdmission(raw, pending)
		if reply.identity != identity || reply.inspectionReason != reason || reply.ready {
			t.Fatal("closed cause lost", reason)
		}
		frame["inspectionReason"] = "PRIVATE-CANARY https://private.invalid"
		raw, _ = json.Marshal(frame)
		reply = decodeCredentialAdmission(raw, pending)
		if reply.identity.DocumentID != "" || CredentialInspectionAttention(reply.inspectionReason) == "PRIVATE-CANARY" {
			t.Fatal("untrusted reason accepted")
		}
	}
	if CredentialInspectionAttention("PRIVATE-CANARY") != "privateInspectionUnavailable" {
		t.Fatal("raw diagnostic projected")
	}
}
