package chrome

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/auth/nativepeer"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/session"
	"github.com/viant/mechanize/vault"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func credentialTestPending() *credentialDeliveryPending {
	return &credentialDeliveryPending{requestID: "private-request", attemptID: strings.Repeat("a", 64), identity: Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 1, FrameID: 0, DocumentID: "document", Generation: 1}, done: make(chan string, 1)}
}
func credentialTestReply(p *credentialDeliveryPending) []byte {
	raw, _ := json.Marshal(struct {
		Type      string   `json:"type"`
		RequestID string   `json:"requestId"`
		AttemptID string   `json:"attemptId"`
		Identity  Identity `json:"identity"`
		Status    string   `json:"status"`
	}{"credentialDeliveryResult", p.requestID, p.attemptID, p.identity, "dispatched"})
	return raw
}
func TestCredentialPayloadCannotEscapePublicFormatting(t *testing.T) {
	secret := credentialPayload{[]byte("user-secret-canary"), []byte("password-secret-canary")}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
		if strings.Contains(fmt.Sprintf(format, secret), "canary") {
			t.Fatal("payload escaped formatting")
		}
	}
	if raw, err := json.Marshal(secret); err == nil || bytes.Contains(raw, []byte("canary")) || strings.Contains(err.Error(), "canary") {
		t.Fatal("payload escaped JSON")
	}
	p := credentialTestPending()
	a := ControlAuthority{Document: Document{Identity: p.identity, Origin: "https://bank.invalid"}, Lease: Lease{ID: "lease", Generation: 1}}
	raw, err := encodeCredentialDelivery(a, p, time.Now().Add(time.Second), secret)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var frame map[string]any
	if json.Unmarshal(raw, &frame) != nil || frame["username"] != "user-secret-canary" || frame["password"] != "password-secret-canary" {
		t.Fatal("private encoder failed")
	}
	for _, key := range []string{"args", "fingerprintSHA256", "value", "action"} {
		if _, ok := frame[key]; ok {
			t.Fatal("generic command field present")
		}
	}
}
func TestCredentialReplyRefusesEchoDuplicateAndIdentityDrift(t *testing.T) {
	p := credentialTestPending()
	good := credentialTestReply(p)
	if decodeCredentialDeliveryReply(good, p) != "dispatched" {
		t.Fatal("closed scalar reply refused")
	}
	cases := [][]byte{
		[]byte(`{"password":"password-secret-canary"}`),
		append(append([]byte(nil), good[:len(good)-1]...), `,"value":"password-secret-canary"}`...),
		append(append([]byte(nil), good[:len(good)-1]...), `,"status":"dispatched"}`...),
		bytes.Replace(good, []byte(`"document"`), []byte(`"different"`), 1),
		bytes.Replace(good, []byte(`"documentGeneration":1`), []byte(`"documentGeneration":2`), 1),
		bytes.Replace(good, []byte(`"dispatched"`), []byte(`"password-secret-canary"`), 1),
		append(good, []byte(` {}`)...),
	}
	for i, raw := range cases {
		if state := decodeCredentialDeliveryReply(raw, p); state != "unknown" || strings.Contains(state, "canary") {
			t.Fatalf("case %d accepted", i)
		}
	}
}
func TestCredentialPrivateDemuxWipesAndNeverJournalsEcho(t *testing.T) {
	p := credentialTestPending()
	c := &channel{privateCredential: p, receipts: map[string]Reply{}, attempts: map[string]Command{}, unknown: map[string]bool{}}
	b := &Broker{}
	raw := []byte(`{"type":"documents","documents":[{"title":"password-secret-canary"}]}`)
	if !b.acceptCredentialDeliveryLocked(c, raw) || <-p.done != "unknown" {
		t.Fatal("private raw frame reached generic route")
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) || len(c.receipts) != 0 || len(c.attempts) != 0 || len(c.documents) != 0 {
		t.Fatal("private echo retained")
	}
}

type credentialFailureWriter struct{}

func (credentialFailureWriter) Write([]byte) (int, error) {
	return 0, errors.New("password-secret-canary")
}
func TestCredentialWriterSanitizesTransportFailure(t *testing.T) {
	err := writeCredentialDelivery(credentialFailureWriter{}, []byte("password-secret-canary"))
	if err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("transport error escaped")
	}
}

type credentialFixtureKeys struct{}

func (credentialFixtureKeys) Resolve(context.Context, string) ([]byte, error) {
	return bytes.Repeat([]byte{19}, 32), nil
}
func TestCredentialDeliveryUsesLocalVaultAndRetainsUnknown(t *testing.T) {
	for _, mode := range []string{"success", "freshExchange", "delayedEcho", "echo", "lost", "scopeDrift", "identityDrift", "credentialDrift", "panic"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := os.MkdirTemp("/private/tmp", "credential-delivery-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(dir)
			p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control", "consent:admin"})
			p.ClientID = "local-client"
			ctx := auth.WithPrincipal(context.Background(), p)
			ctx = auth.WithConsentBinding(ctx, auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "credential entry"})
			ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			parent := session.ProcessIdentity{PID: 10, UID: uint32(os.Getuid()), Executable: "/fixture/chrome", StartToken: "parent-start"}
			host := session.ProcessIdentity{PID: 20, UID: uint32(os.Getuid()), Executable: "/fixture/host", StartToken: "host-start"}
			evidence := nativepeer.ChromeProcessEvidence{NativeHost: host, ChromeParent: parent, Ancestors: []session.ProcessIdentity{parent}, KernelPeerQualified: true}
			grant := Enrollment{Principal: p, ProfileChannel: "profile", BrowserInstance: "browser", ExtensionOrigin: "chrome-extension://" + strings.Repeat("a", 32) + "/", Origins: []string{"https://bank.invalid"}, ProfileDirectory: dir}
			b, err := newBrokerWithPeer(Config{SocketPath: filepath.Join(dir, "broker.sock"), Grants: []Enrollment{grant}}, map[string]string{channelKey("profile", "browser"): strings.Repeat("x", 64)}, func(context.Context, *net.UnixConn) (nativepeer.ChromeProcessEvidence, error) { return evidence, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			conn, err := net.Dial("unix", b.listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
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
			a, c, err := g.controlSnapshot(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin})
			if err != nil {
				t.Fatal(err)
			}
			a.Lease = Lease{ID: "lease", Generation: 1}
			g.setControlLocked(a)
			store, err := vault.NewStore(filepath.Join(dir, "vault"), "fixture-v1", &vault.Cipher{Keys: credentialFixtureKeys{}})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			human, err := auth.WithNativeHuman(ctx)
			if err != nil {
				t.Fatal(err)
			}
			target := vault.Target{Origin: doc.Origin, Account: "account"}
			ref, err := store.Create(human, target, []byte("user-secret-canary"), []byte("password-secret-canary"))
			if err != nil {
				t.Fatal(err)
			}
			meta, err := store.Metadata(human, target)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "credentialDrift" {
				if _, err = store.Update(human, target, meta.Revision, []byte("changed-user-canary"), []byte("changed-password-canary")); err != nil {
					t.Fatal(err)
				}
			}
			binding := vault.Binding{SessionID: "session", DocumentID: doc.DocumentID, NavigationID: CredentialNavigationID(a), Target: target}
			manager, _ := vault.NewManager(store, vault.Hooks{Present: func(context.Context, vault.Request) error { return errors.New("unneeded") }, Resume: func(context.Context, vault.Binding, vault.Reference) error { return errors.New("unneeded") }, Fresh: func(freshCtx context.Context, v vault.Binding) (vault.Binding, error) {
				if mode == "freshExchange" {
					select {
					case b.lane <- struct{}{}:
						defer func() { <-b.lane }()
					case <-freshCtx.Done():
						return vault.Binding{}, freshCtx.Err()
					}
					c.writeMu.Lock()
					defer c.writeMu.Unlock()
					b.mu.Lock()
					deliveryInstalled := c.privateCredential != nil
					b.mu.Unlock()
					if deliveryInstalled {
						return vault.Binding{}, errors.New("delivery intercepted fresh probe")
					}
				}
				if mode == "scopeDrift" {
					v.Target.Origin = "https://other.invalid"
				}
				if mode == "panic" {
					panic("password-secret-canary")
				}
				return v, nil
			}})
			received := make(chan bool, 1)
			go func() {
				raw, e := ReadFrame(conn)
				if e != nil {
					return
				}
				defer clear(raw)
				var frame map[string]json.RawMessage
				if json.Unmarshal(raw, &frame) != nil {
					return
				}
				received <- true
				if mode == "lost" {
					conn.Close()
					return
				}
				var requestID, attemptID string
				json.Unmarshal(frame["requestId"], &requestID)
				json.Unmarshal(frame["attemptId"], &attemptID)
				pending := &credentialDeliveryPending{requestID: requestID, attemptID: attemptID, identity: doc.Identity}
				reply := credentialTestReply(pending)
				if mode == "echo" {
					reply = append(reply[:len(reply)-1], `,"value":"password-secret-canary"}`...)
				}
				if mode == "identityDrift" {
					b.mu.Lock()
					c.documents[0].Generation++
					b.mu.Unlock()
				}
				WriteFrame(conn, json.RawMessage(reply))
				if mode == "delayedEcho" {
					WriteFrame(conn, map[string]any{"type": "documents", "documents": []map[string]any{{"title": "password-secret-canary"}}})
				}
				clear(reply)
			}()
			attempt := strings.Repeat("b", 64)
			result, err := g.DeliverVaultCredential(ctx, p, a, attempt, manager, binding, ref, meta.Revision, func(context.Context) error { return nil })
			output := fmt.Sprintf("%+v %v", result, err)
			if strings.Contains(output, "canary") {
				t.Fatal("secret escaped public outcome")
			}
			expected := "unknown"
			if mode == "success" || mode == "freshExchange" || mode == "delayedEcho" {
				expected = "dispatched"
			}
			if mode == "scopeDrift" || mode == "credentialDrift" || mode == "panic" {
				expected = "notDispatched"
				select {
				case <-received:
					t.Fatal("refused delivery wrote credentials")
				default:
				}
			}
			if mode == "delayedEcho" && result.DispatchState == "unknown" {
				expected = "unknown"
			}
			if mode == "scopeDrift" && result.FailureStage != "privateBindingFresh" {
				t.Fatal("stale recipient was misreported as a Vault read failure", result)
			}
			if mode == "credentialDrift" && result.FailureStage != "localVaultRead" {
				t.Fatal("selected revision failure was misreported", result)
			}
			if result.DispatchState != expected || (expected == "dispatched" && err != nil) || (expected != "dispatched" && err == nil) {
				t.Fatalf("unexpected scalar outcome: %s", output)
			}
			b.mu.Lock()
			unknown := c.unknown[attempt]
			for _, d := range c.documents {
				if strings.Contains(d.Title, "canary") {
					t.Fatal("delayed private echo entered public inventory")
				}
			}
			public, _ := json.Marshal(struct {
				Attempts map[string]Command
				Receipts map[string]Reply
			}{c.attempts, c.receipts})
			b.mu.Unlock()
			if strings.Contains(string(public), "canary") || len(public) > 40 {
				t.Fatal("private attempt entered public journal")
			}
			if unknown != (expected == "unknown") {
				t.Fatal("unknown barrier incorrect")
			}
			again, e := g.DeliverVaultCredential(ctx, p, a, attempt, manager, binding, ref, meta.Revision, func(context.Context) error { return nil })
			if e == nil || again.DispatchState != "notDispatched" {
				t.Fatal("attempt replay allowed")
			}
		})
	}
}
