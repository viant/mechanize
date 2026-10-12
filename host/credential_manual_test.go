package host

import (
	"context"
	"errors"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/vault"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManualResumeSourceComesOnlyFromOwnedKnownImmutableRows(t *testing.T) {
	p, _ := auth.NewPrincipal("fixture", "", "owner", []string{"desktop:control"})
	p.ClientID = "client"
	prep := data.CredentialPreparationRecord{Namespace: p.Namespace, ClientID: p.ClientID, PreparationID: strings.Repeat("a", 64), SelectedRevision: strings.Repeat("b", 64), Origin: "https://fixture.invalid", ProtectionState: "held", Revision: 1}
	row := data.CredentialDeliveryRecord{Namespace: p.Namespace, ClientID: p.ClientID, SelectionID: prep.PreparationID, SelectedRevision: prep.SelectedRevision, Origin: prep.Origin, ChromeStartToken: "123:456", TabID: 7, DocumentID: "original", DocumentGeneration: 1, ProfileChannel: "profile", BrowserInstance: "browser", DispatchState: "dispatched", ProtectionState: "held", Revision: 2}
	for _, mode := range []string{"known", "closedKnown", "unknown", "notDispatched", "foreignOwner", "foreignClient", "missing", "revision", "origin", "document", "tab", "birth", "inconsistentBirth", "parentClosed"} {
		r := row
		parent := prep
		rows := []data.CredentialDeliveryRecord{r}
		switch mode {
		case "closedKnown":
			r.ProtectionState = "closed"
		case "unknown":
			r.DispatchState = "unknown"
		case "notDispatched":
			r.DispatchState = "notDispatched"
		case "foreignOwner":
			r.Namespace = "foreign"
		case "foreignClient":
			r.ClientID = "foreign"
		case "missing":
			rows = nil
		case "revision":
			r.SelectedRevision = "different"
		case "origin":
			r.Origin = "https://foreign.invalid"
		case "document":
			r.DocumentID = ""
		case "tab":
			r.TabID = 0
		case "birth":
			r.ChromeStartToken = ""
		case "inconsistentBirth":
			extra := r
			extra.ChromeStartToken = "234:567"
			rows = append(rows, extra)
		case "parentClosed":
			parent.ProtectionState = "closed"
		}
		if len(rows) > 0 {
			rows[0] = r
		}
		source, e := manualCredentialSource(p, parent, rows)
		valid := mode == "known" || mode == "closedKnown"
		if (e == nil) != valid {
			t.Fatal("untrusted manual source admitted", mode)
		}
		if valid && (source.Identity.TabID != 7 || source.ChromeBirth != "123:456" || source.Origin != prep.Origin) {
			t.Fatal("original immutable source changed")
		}
	}
}

func TestManualPrivacyAttentionOnlyClosedPhases(t *testing.T) {
	for _, row := range [][2]string{{"source", "manualPrivacySourceUnavailable"}, {"consent", "manualPrivacyConsentUnavailable"}, {"absence", "manualPrivacyAbsenceUnavailable"}, {"staging", "manualPrivacyStagingUnavailable"}, {"selection", "manualPrivacySelectionUnavailable"}, {"qualification", "manualPrivacyQualificationUnavailable"}, {"transition", "manualPrivacyTransitionUnavailable"}, {"cleanup", "manualPrivacyCleanupUnavailable"}, {"PRIVATE-CANARY", "postSubmitPrivacyUnavailable"}} {
		if got := manualPrivacyAttention(row[0], errors.New("PRIVATE-CANARY sourceTabPresent")); got != row[1] {
			t.Fatal("raw diagnostic escaped", got)
		}
	}
}

func TestManualHostPrivateSeedChainAndClosedResolverFailure(t *testing.T) {
	for _, mode := range []string{"known", "refused", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			p, _ := auth.NewPrincipal("fixture", "", "manual-host", []string{"desktop:control", "consent:admin"})
			p.ClientID = "client"
			ctx := auth.WithConsentBinding(auth.WithPrincipal(context.Background(), p), auth.ConsentBinding{SessionID: "session", GrantID: "grant", Purpose: "manual recovery"})
			human, _ := auth.WithNativeHuman(ctx)
			base, e := filepath.EvalSymlinks(t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			root := filepath.Join(base, "records")
			if e := os.Mkdir(root, 0700); e != nil {
				t.Fatal(e)
			}
			store, e := vault.NewRecordStore(root, "fixture", &vault.Cipher{Keys: credentialFixtureKey{}})
			if e != nil {
				t.Fatal(e)
			}
			values, e := vault.NewRecordValues([]byte("synthetic-key"), [][2][]byte{{[]byte("$scy.type"), []byte("basic")}, {[]byte("endpoint"), []byte("https://fixture.invalid")}, {[]byte("username"), []byte("synthetic-user")}, {[]byte("password"), []byte("synthetic-password")}})
			if e != nil {
				t.Fatal(e)
			}
			meta, e := store.Create(human, values)
			if e != nil {
				t.Fatal(e)
			}
			gate, e := vault.NewGuardedExposureGate(func(context.Context) error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			binding := vault.Binding{SessionID: "session", DocumentID: "original", NavigationID: strings.Repeat("a", 64), Target: vault.Target{Origin: "https://fixture.invalid", Account: "opaque"}}
			guard := func(context.Context) error { return nil }
			protected, e := gate.BeginManualDOMTransition(ctx, binding, guard)
			if e != nil {
				t.Fatal(e)
			}
			selected, revision, e := vault.ResolveOriginRecordDelivery(ctx, store, binding.Target, time.Now().Add(time.Minute), guard)
			if e != nil || revision != meta.Revision {
				t.Fatal("selection failed")
			}
			defer selected.Revoke()
			manager, e := vault.NewRecordDeliveryManager(selected, func(c context.Context, b vault.Binding) (vault.Binding, error) {
				if b != binding || protected.Verify(c, binding) != nil {
					return vault.Binding{}, errPrivateCredential
				}
				return binding, nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if mode == "revoked" {
				selected.Revoke()
			}
			callbacks := 0
			sentinel := errors.New("synthetic private resolver refusal")
			next := binding
			next.DocumentID = "manual"
			next.NavigationID = strings.Repeat("b", 64)
			_, dom, e := manualTransitionDOM(ctx, protected, binding, func(c context.Context) (vault.Binding, error) {
				err := selected.UseBinding(c, binding, func(ref vault.Reference, revision string) error {
					return manager.ConsumeRevision(c, binding, ref, revision, func(secret vault.Credentials) error {
						return secret.WithBytes(func(user, password []byte) error {
							callbacks++
							if len(user) == 0 || len(password) == 0 {
								t.Fatal("private bytes unavailable")
							}
							if mode == "refused" {
								return sentinel
							}
							return nil
						})
					})
				})
				if err != nil {
					return vault.Binding{}, err
				}
				return next, nil
			})
			if mode == "known" {
				if e != nil || callbacks != 1 || dom.VerifyDOM(ctx, next) != nil {
					t.Fatal("production preseed chain failed", e)
				}
			} else {
				if e == nil || mode == "refused" && errors.Is(e, sentinel) || mode == "revoked" && callbacks != 0 {
					t.Fatal("private denial lost", e)
				}
			}
			if _, e := gate.AcquireExposureContext(ctx); !errors.Is(e, vault.ErrDeliveryProtected) {
				t.Fatal("qualification released exposure")
			}
		})
	}
}
