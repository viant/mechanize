package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

// This exercises the production method composition against a synthetic signed
// peer and encrypted fixture store. It proves protocol/lock composition, not a
// real browser, consent provider, Keychain custody or live account outcome.
func TestCredentialManagerFreshToPrivateDeliveryIntegration(t *testing.T) {
	for _, mode := range []string{"success", "generationDrift"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
			dir, err := os.MkdirTemp("/private/tmp", "credential-manager-seam-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(dir) })
			store, err := vault.NewStore(filepath.Join(dir, "vault"), "fixture-v1", &vault.Cipher{Keys: credentialFixtureKeys{}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			humanPrincipal := p
			humanPrincipal.Scopes = append(append([]string(nil), p.Scopes...), "consent:admin")
			human, err := auth.WithNativeHuman(auth.WithPrincipal(ctx, humanPrincipal))
			if err != nil {
				t.Fatal(err)
			}
			target := vault.Target{Origin: doc.Origin, Account: "synthetic-selected-account"}
			ref, err := store.Create(human, target, []byte("fixture-user-canary"), []byte("fixture-password-canary"))
			if err != nil {
				t.Fatal(err)
			}
			selected, err := store.Metadata(human, target)
			if err != nil {
				t.Fatal(err)
			}

			type exchange struct {
				kind  string
				valid bool
			}
			exchanges := make(chan exchange, 8)
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				var held Lease
				for {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var frame map[string]json.RawMessage
					if json.Unmarshal(raw, &frame) != nil {
						clear(raw)
						return
					}
					clear(raw)
					var kind, action, id, attempt string
					var identity Identity
					json.Unmarshal(frame["type"], &kind)
					json.Unmarshal(frame["action"], &action)
					json.Unmarshal(frame["requestId"], &id)
					json.Unmarshal(frame["identity"], &identity)
					switch {
					case kind == "credentialInspect":
						fresh := frame["controlLease"] != nil
						if fresh {
							var lease Lease
							json.Unmarshal(frame["controlLease"], &lease)
							g.broker.mu.Lock()
							demux := c.privateInspection != nil && c.privateCredential == nil
							g.broker.mu.Unlock()
							exchanges <- exchange{"fresh", demux && lease == held && held.ID != "" && len(frame) == 9}
							if mode == "generationDrift" {
								identity.Generation++
							}
						} else {
							exchanges <- exchange{"admit", len(frame) == 8}
						}
						e = WriteFrame(conn, map[string]any{"type": "credentialInspectResult", "privateCredentialProtocolVersion": 2, "stage": "pair", "requestId": id, "identity": identity, "ready": true})
					case action == "executor.acquire":
						json.Unmarshal(frame["controlLease"], &held)
						exchanges <- exchange{"acquire", held.ID != ""}
						e = WriteFrame(conn, map[string]any{"requestId": id, "identity": identity, "validated": true, "controlLease": held})
					case kind == "credentialDelivery":
						var username, password string
						var lease Lease
						json.Unmarshal(frame["username"], &username)
						json.Unmarshal(frame["password"], &password)
						json.Unmarshal(frame["attemptId"], &attempt)
						json.Unmarshal(frame["controlLease"], &lease)
						g.broker.mu.Lock()
						demux := c.privateCredential != nil && c.privateInspection != nil
						g.broker.mu.Unlock()
						valid := demux && lease == held && identity == doc.Identity && username == "fixture-user-canary" && password == "fixture-password-canary"
						username = ""
						password = ""
						exchanges <- exchange{"delivery", valid}
						e = WriteFrame(conn, map[string]any{"type": "credentialDeliveryResult", "requestId": id, "attemptId": attempt, "identity": identity, "status": "dispatched"})
					default:
						exchanges <- exchange{"unexpected", false}
						conn.Close()
						return
					}
					for _, value := range frame {
						clear(value)
					}
					if e != nil {
						return
					}
				}
			}()
			allow := func(context.Context) error { return nil }
			admitted, err := g.AdmitCredentialControl(ctx, p, model.Surface{Kind: "web", Origin: doc.Origin}, allow)
			if err != nil || !admitted.Confirmed {
				t.Fatal("secure fixture admission failed", err)
			}
			authority := admitted.Authority
			binding := vault.Binding{SessionID: "session", DocumentID: doc.DocumentID, NavigationID: CredentialNavigationID(authority), Target: target}
			var freshCalls atomic.Int32
			manager, err := vault.NewManager(store, vault.Hooks{
				Present: func(context.Context, vault.Request) error { return errors.New("unexpected presentation") },
				Resume:  func(context.Context, vault.Binding, vault.Reference) error { return errors.New("unexpected resume") },
				Fresh: func(freshCtx context.Context, value vault.Binding) (vault.Binding, error) {
					freshCalls.Add(1)
					if auth.NativeHuman(freshCtx) {
						return vault.Binding{}, errors.New("automation identity replaced")
					}
					return g.FreshCredentialBinding(freshCtx, p, authority, value, allow)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			attempt := strings.Repeat("b", 64)
			result, err := g.DeliverVaultCredential(ctx, p, authority, attempt, manager, binding, ref, selected.Revision, allow)
			if freshCalls.Load() != 1 {
				t.Fatal("real Manager Fresh hook was not invoked exactly once")
			}
			if mode == "success" {
				if err != nil || result.DispatchState != "dispatched" || ctx.Err() != nil {
					t.Fatal("actual Fresh and delivery seam failed or deadlocked", err)
				}
			} else if err == nil || result.DispatchState != "notDispatched" {
				t.Fatal("generation drift reached credential delivery")
			}
			// Successful delivery retains a quarantined continuation channel; explicit
			// cancellation closes it without returning delayed frames to public parsing.
			if mode == "success" {
				if g.CancelVaultCredential(ctx, p, authority) != nil {
					t.Fatal("private cancellation failed")
				}
			}
			select {
			case <-stopped:
			case <-ctx.Done():
				t.Fatal("private connection was not closed")
			}
			close(exchanges)
			expected := []string{"admit", "acquire", "fresh"}
			if mode == "success" {
				expected = append(expected, "delivery")
			}
			n := 0
			for exchange := range exchanges {
				if !exchange.valid || n >= len(expected) || exchange.kind != expected[n] {
					t.Fatal("wrong protocol ordering, held lease or private demux")
				}
				n++
			}
			if n != len(expected) {
				t.Fatal("missing expected private frame")
			}
			g.broker.mu.Lock()
			public, _ := json.Marshal(struct {
				Attempts  map[string]Command
				Receipts  map[string]Reply
				Documents []Document
			}{c.attempts, c.receipts, c.documents})
			marked := c.privateCredentialAttempts[attempt]
			g.broker.mu.Unlock()
			if strings.Contains(string(public), "canary") {
				t.Fatal("fixture credential entered public state")
			}
			if marked != (mode == "success") {
				t.Fatal("fresh refusal created a delivery attempt")
			}
			g.controlMu.Lock()
			retained := g.control
			g.controlMu.Unlock()
			if retained == nil || !sameControl(*retained, authority) {
				t.Fatal("seam adopted changed renderer authority")
			}
		})
	}
}
