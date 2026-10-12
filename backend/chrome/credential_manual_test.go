package chrome

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManualTabAbsenceIsClosedAndNeverGrantsFromRefusal(t *testing.T) {
	for _, mode := range []string{"absent", "present", "incomplete", "foreign", "raw", "duplicate", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
			source := ManualCredentialSource{Identity: doc.Identity, Origin: doc.Origin, ChromeBirth: c.processEvidence.ChromeParent.StartToken}
			go func() {
				raw, e := ReadFrame(conn)
				if e != nil {
					return
				}
				var q struct {
					Type, RequestID, ProofID string
					SourceIdentity           Identity
				}
				json.Unmarshal(raw, &q)
				if q.Type != "credentialTabAbsent" {
					t.Error("manual absence sent input")
				}
				id := q.SourceIdentity
				if mode == "foreign" {
					id.TabID++
				}
				frame := map[string]any{"type": "credentialTabAbsentResult", "requestId": q.RequestID, "proofId": q.ProofID, "sourceIdentity": id, "absent": mode == "absent", "inventoryComplete": mode != "incomplete"}
				if mode != "absent" {
					frame["reason"] = "sourceTabPresent"
				}
				if mode == "raw" {
					frame["error"] = "PRIVATE_CANARY"
				}
				if mode == "unknown" {
					frame["reason"] = "PRIVATE_CANARY"
				}
				raw, _ = json.Marshal(frame)
				if mode == "duplicate" {
					raw = append(raw[:len(raw)-1], `,"proofId":"changed"}`...)
				}
				WriteFrame(conn, json.RawMessage(raw))
			}()
			transition, e := g.BeginManualCredentialPrivacy(ctx, p, source, func(context.Context) error { return nil })
			if (e == nil) != (mode == "absent") {
				t.Fatal("absence refusal granted authority", mode)
			}
			if mode == "present" || mode == "incomplete" {
				if ManualCredentialPrivacyReason(e) != "sourceTabPresent" {
					t.Fatal("closed refusal lost")
				}
			} else if ManualCredentialPrivacyReason(e) != "" {
				t.Fatal("unvalidated denial projected a reason")
			}
			if transition != nil {
				transition.Abort()
			}
			if mode == "present" || mode == "incomplete" {
				g.broker.mu.Lock()
				connected := c.conn != nil
				g.broker.mu.Unlock()
				if !connected {
					t.Fatal("validated negative destroyed owned connection")
				}
			}
		})
	}
}
func TestManualPrivateSeedCannotEnterGenericMarshalOrPublicReply(t *testing.T) {
	secret := credentialPayload{[]byte("USER_CANARY"), []byte("PASSWORD_CANARY")}
	if _, e := json.Marshal(map[string]any{"privateSeed": secret}); e == nil {
		t.Fatal("generic secret marshal admitted")
	}
	raw, e := encodeManualCredentialSeed([]byte(`{"type":"credentialManualPrivacy"}`), secret)
	if e != nil || !json.Valid(raw) {
		t.Fatal(e)
	}
	clear(raw)
	frame := []byte(`{"type":"credentialManualPrivacyResult","requestId":"r","proofId":"p","identity":null,"ready":false,"redactionReady":false,"privateInputRetired":false,"reason":"documentNotReady","password":"PASSWORD_CANARY"}`)
	var out struct{}
	if decodeManualReply(frame, &out) == nil {
		t.Fatal("private value entered scalar response")
	}
	if !strings.Contains(ErrManualCredentialPrivacy.Error(), "unavailable") {
		t.Fatal("private error unsafe")
	}
}

func TestManualControlRetiresOnlyCapturedOwnedSource(t *testing.T) {
	p := auth.Principal{Namespace: "owner", ClientID: "client"}
	source := ManualCredentialSource{Identity: Identity{ProfileChannel: "profile", BrowserInstance: "browser", TabID: 7, DocumentID: "old"}}
	a := ControlAuthority{Owner: p.Namespace, ClientID: p.ClientID, Document: Document{Identity: source.Identity}}
	if !manualControlOwned(&a, p, source, nil) {
		t.Fatal("owned source rejected")
	}
	for _, mode := range []string{"owner", "client", "tab", "document", "browser"} {
		other := a
		switch mode {
		case "owner":
			other.Owner = "foreign"
		case "client":
			other.ClientID = "foreign"
		case "tab":
			other.Document.TabID++
		case "document":
			other.Document.DocumentID = "new"
		case "browser":
			other.Document.BrowserInstance = "foreign"
		}
		if manualControlOwned(&other, p, source, nil) {
			t.Fatal("unrelated control retired", mode)
		}
	}
	next := a
	next.Document.TabID = 8
	next.Document.DocumentID = "manual"
	prior := &credentialPrivacyState{active: true, published: true, authority: next}
	if !manualControlOwned(&next, p, source, prior) {
		t.Fatal("exact prior DOM control cannot refresh")
	}
	changed := next
	changed.Lease.ID = "another"
	if manualControlOwned(&changed, p, source, prior) {
		t.Fatal("new lease borrowed")
	}
}

func TestManualPrivacyReasonCannotProjectRawError(t *testing.T) {
	for _, reason := range []string{"invalidRequest", "authorityChanged", "expired", "busy", "unknownEffects", "lifecycleInhibited", "sourceTabPresent", "inventoryUnavailable", "candidateUnavailable", "candidateAmbiguous", "candidateChanged", "documentNotReady", "redactionUnavailable"} {
		e := manualRefusal(reason)
		if ManualCredentialPrivacyReason(e) != reason || !errors.Is(e, ErrManualCredentialPrivacy) {
			t.Fatal("closed reason missing")
		}
	}
	for _, e := range []error{nil, errors.New("PRIVATE-CANARY"), errors.New("sourceTabPresent"), manualRefusal("PRIVATE-CANARY")} {
		if ManualCredentialPrivacyReason(e) != "" {
			t.Fatal("raw error projected")
		}
	}
}

func TestManualQualificationRetainsOnlyValidatedReasonAcrossVaultConsumer(t *testing.T) {
	for _, mode := range []string{"candidateUnavailable", "raw"} {
		t.Run(mode, func(t *testing.T) {
			g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
			base, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(base, "records")
			if e = os.Mkdir(root, 0700); e != nil {
				t.Fatal(e)
			}
			store, e := vault.NewRecordStore(root, "fixture-v1", &vault.Cipher{Keys: credentialFixtureKeys{}})
			if e != nil {
				t.Fatal(e)
			}
			admin := p
			admin.Scopes = append(append([]string(nil), p.Scopes...), "consent:admin")
			human, _ := auth.WithNativeHuman(auth.WithPrincipal(ctx, admin))
			values, _ := vault.NewRecordValues([]byte("synthetic-key"), [][2][]byte{{[]byte("$scy.type"), []byte("basic")}, {[]byte("endpoint"), []byte(doc.Origin)}, {[]byte("username"), []byte("synthetic-user")}, {[]byte("password"), []byte("synthetic-password")}})
			if _, e = store.Create(human, values); e != nil {
				t.Fatal(e)
			}
			b := vault.Binding{SessionID: "session", DocumentID: doc.DocumentID, NavigationID: strings.Repeat("a", 64), Target: vault.Target{Origin: doc.Origin, Account: "opaque"}}
			selected, revision, e := vault.ResolveOriginRecordDelivery(ctx, store, b.Target, time.Now().Add(time.Minute), func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			defer selected.Revoke()
			manager, e := vault.NewRecordDeliveryManager(selected, func(_ context.Context, actual vault.Binding) (vault.Binding, error) { return actual, nil })
			if e != nil {
				t.Fatal(e)
			}
			go func() {
				for i := 0; i < 2; i++ {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var q struct {
						RequestID, ProofID, Type string
						SourceIdentity           Identity
					}
					json.Unmarshal(raw, &q)
					clear(raw)
					if q.Type == "credentialTabAbsent" {
						WriteFrame(conn, map[string]any{"type": "credentialTabAbsentResult", "requestId": q.RequestID, "proofId": q.ProofID, "sourceIdentity": q.SourceIdentity, "absent": true, "inventoryComplete": true})
					} else {
						reason := mode
						if mode == "raw" {
							reason = "PRIVATE-CANARY"
						}
						WriteFrame(conn, map[string]any{"type": "credentialManualPrivacyResult", "requestId": q.RequestID, "proofId": q.ProofID, "identity": nil, "ready": false, "redactionReady": false, "privateInputRetired": false, "reason": reason})
					}
				}
			}()
			tr, e := g.BeginManualCredentialPrivacy(ctx, p, ManualCredentialSource{Identity: doc.Identity, Origin: doc.Origin, ChromeBirth: c.processEvidence.ChromeParent.StartToken}, func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			defer tr.Abort()
			// UseBinding also hides errors; capture the direct provider result inside its
			// synchronous callback exactly as Host does for closed diagnostics.
			var direct error
			e = selected.UseBinding(ctx, b, func(ref vault.Reference, rev string) error {
				if rev != revision {
					t.Fatal("revision changed")
				}
				_, direct = tr.Qualify(ctx, p, manager, b, ref, rev)
				return direct
			})
			if e == nil {
				t.Fatal("negative qualification succeeded")
			}
			want := ""
			if mode != "raw" {
				want = mode
			}
			if got := ManualCredentialPrivacyReason(direct); got != want {
				t.Fatal("validated reason lost or raw projected", got)
			}
		})
	}
}

func TestManualDocumentAbsenceModeIsNegotiatedAndFrozen(t *testing.T) {
	for _, version := range []int{0, 1, 2} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			g, p, ctx, conn, c, doc := credentialAdmissionFixture(t)
			c.manualPrivacyDocumentVersion = version
			source := ManualCredentialSource{Identity: doc.Identity, Origin: doc.Origin, ChromeBirth: c.processEvidence.ChromeParent.StartToken}
			observed := make(chan bool, 3)
			go func() {
				for phase := 0; phase < 3; phase++ {
					raw, e := ReadFrame(conn)
					if e != nil {
						return
					}
					var q map[string]json.RawMessage
					if json.Unmarshal(raw, &q) != nil {
						return
					}
					opted, exists := q["sourceDocumentAbsence"]
					observed <- exists && string(opted) == "true"
					var requestID, proofID string
					json.Unmarshal(q["requestId"], &requestID)
					json.Unmarshal(q["proofId"], &proofID)
					if phase == 0 {
						WriteFrame(conn, map[string]any{"type": "credentialTabAbsentResult", "requestId": requestID, "proofId": proofID, "sourceIdentity": source.Identity, "absent": true, "inventoryComplete": true})
					} else {
						WriteFrame(conn, map[string]any{"type": "credentialManualPrivacyResult", "requestId": requestID, "proofId": proofID, "identity": nil, "ready": false, "redactionReady": false, "privateInputRetired": false, "reason": "documentNotReady"})
					}
				}
			}()
			transition, e := g.BeginManualCredentialPrivacy(ctx, p, source, func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			defer transition.Abort()
			// Capability changes cannot silently upgrade/downgrade a held transition.
			g.broker.mu.Lock()
			c.manualPrivacyDocumentVersion = 1 - version
			g.broker.mu.Unlock()
			for _, kind := range []string{"credentialManualPrivacy", "credentialManualPrivacyCommit"} {
				raw, e := transition.exchange(ctx, p, kind, nil)
				clear(raw)
				if e != nil {
					t.Fatal(e)
				}
			}
			for phase := 0; phase < 3; phase++ {
				if got := <-observed; got != (version == 1) {
					t.Fatal("private phase changed negotiated mode", phase)
				}
			}
		})
	}
}
