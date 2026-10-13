package host

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/consent"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/script"
	"github.com/viant/mechanize/vault"
)

func TestWebNavigationUsesPinnedPublicSourceWhileUnrelatedLoginHeld(t *testing.T) {
	credentialHostFixtureFlow(t, "pinnedPublicNavigation", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, in gateway.CredentialPrepareInput, private *credentialBrowserFixture, reads *atomic.Int64) {
		original := private.session
		bound := auth.WithConsentBinding(ctx, original.consent)
		// Keep a real original UNKNOWN row, not just an in-memory protection flag.
		if _, err := h.CredentialApply(ctx, p, ref); err != nil {
			t.Fatal(err)
		}
		private.submitUnknown = true
		if _, err := h.CredentialSubmit(ctx, p, ref); err != nil {
			t.Fatal(err)
		}
		history := func() string {
			var encoded []byte
			err := h.durable.WithCredentialDeliveryComponents(bound, p, func(c context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
				prep, rows, e := h.durable.LoadCredentialRecovery(c, p, ref.PreparationID)
				if e != nil {
					return e
				}
				encoded, e = json.Marshal(struct {
					Prep any
					Rows any
				}{prep, rows})
				return e
			})
			if err != nil {
				t.Fatal(err)
			}
			return string(encoded)
		}
		before := history()
		beforeReads := reads.Load()
		fills, submits := private.fills, private.submits
		publicOrigin := "http://localhost:9192"
		scopes, err := h.durable.CredentialProtectionScopes(bound, p, publicOrigin)
		if err != nil || len(scopes) == 0 || scopes[0].Scope.Origin != in.Surface.Origin {
			t.Fatal("reader incorrectly origin-filtered", err)
		}
		for _, mode := range []string{"public", "destinationLogin", "destinationDenied", "protected", "proofUnavailable", "stale"} {
			t.Run(mode, func(t *testing.T) {
				f := newWebControlFixture(t)
				f.principal = p
				f.ctx = bound
				f.ready.Authority.Owner = p.Namespace
				f.ready.Authority.Document.Origin = publicOrigin
				f.ready.Authority.Document.ProfileChannel = "profile"
				f.ready.Authority.Document.BrowserInstance = "browser"
				f.ready.Authority.Document.TabID = 8
				f.enrollment.Profiles[0].Origins = []string{publicOrigin}
				f.enrollment.Profiles[0].ProfileChannel = "profile"
				f.enrollment.Profiles[0].BrowserInstance = "browser"
				f.ready.Actions = append(f.ready.Actions, "browser.navigate")
				plan, e := script.Compile(`web.tab(origin:"http://localhost:9192").navigate("http://localhost:9192/next")`)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "destinationLogin" || mode == "destinationDenied" {
					plan.Steps[0].Arguments["url"] = model.Value{Kind: model.StringValue, String: in.Surface.Origin + "/login"}
				}
				plan.Steps[0].Effect.BusinessKey = map[string]model.Value{"case": {Kind: model.StringValue, String: mode}}
				f.step = plan.Steps[0]
				checks := 0
				private.scopeDisjoint = func(c context.Context, source chrome.CredentialProtectionScope, target model.Surface) error {
					checks++
					if source.PreparationID != ref.PreparationID || target.Origin != publicOrigin || target.TabID != f.ready.Authority.Document.QualifiedTabID() {
						t.Error("authorization lost pinned exact source")
					}
					if mode == "protected" {
						return vault.ErrDeliveryProtected
					}
					if mode == "proofUnavailable" {
						return errors.New("private-error-canary")
					}
					return c.Err()
				}
				f.manager.options.Authorize = func(c context.Context, a auth.Principal, s model.Surface) (*consent.Lease, error) {
					return h.AuthorizeOperation(c, a, s, true, consent.Control)
				}
				destinationChecks := 0
				f.manager.options.authorizeDestination = func(c context.Context, a auth.Principal, s model.Surface) (*consent.Lease, error) {
					destinationChecks++
					if s.Origin != in.Surface.Origin || s.TabID != "" {
						t.Error("destination acquired a document")
					}
					if mode == "destinationDenied" {
						return nil, auth.ErrUnauthorized
					}
					return h.authorizeConsentOperation(c, a, s, true, consent.Control)
				}
				if mode == "stale" {
					f.verifyErr = errors.New("fixture stale pin")
				}
				h.webControl = f.manager
				defer func() { h.webControl = nil }()
				f.manager.options.ExecutePinned = func(c context.Context, a auth.Principal, s model.Step, _ map[string]model.Value, authority WebControlAuthority) (integration.StepResult, error) {
					f.dispatches++
					if authority != f.ready.Authority || s.Target.Surface.TabID != "" {
						t.Error("authored intent or authority rewritten")
					}
					if e := original.protected.WithDelivery(c, original.binding, func() error { t.Error("private input overlapped navigation"); return nil }); e == nil {
						t.Error("no private exclusion")
					}
					return integration.StepResult{DispatchState: "dispatched", VerificationState: "unverified"}, nil
				}
				op, e := h.Runtime.StartPlan(bound, ref.SessionID, *plan, nil)
				if e != nil {
					t.Fatal(e)
				}
				wait, cancel := context.WithTimeout(bound, 15*time.Second)
				defer cancel()
				result, e := h.Runtime.Wait(wait, ref.SessionID, op.ID)
				if e != nil {
					t.Fatal(e)
				}
				if mode == "public" || mode == "destinationLogin" {
					if f.dispatches != 1 || checks != 1 {
						t.Fatalf("public navigation blocked: dispatch=%d checks=%d status=%s error=%s qualifications=%d verifications=%d", f.dispatches, checks, result.Status, result.Error, f.qualifications, f.verifications)
					}
				} else if f.dispatches != 0 {
					t.Fatal("protected/stale source dispatched")
				}
				if mode == "protected" || mode == "proofUnavailable" {
					failure, e := h.Runtime.ExecutionFailure(bound, ref.SessionID, op.ID)
					want := "privateDOMUnavailable"
					if mode == "proofUnavailable" {
						want = "publicReadUnavailable"
					}
					if e != nil || failure == nil || failure.Code != want || failure.DispatchState != "notDispatched" || strings.Contains(result.Error, "private-error-canary") {
						t.Fatal("closed pre-input failure lost", failure, e)
					}
				}
				if mode == "destinationLogin" || mode == "destinationDenied" {
					if destinationChecks != 1 {
						t.Fatal("destination consent not checked")
					}
				}
			})
		}
		private.scopeDisjoint = func(context.Context, chrome.CredentialProtectionScope, model.Surface) error {
			return vault.ErrDeliveryProtected
		}
		if lease, e := h.AuthorizeOperation(bound, p, model.Surface{Kind: "web", Origin: in.Surface.Origin, TabID: "profile/browser/7"}, true, consent.Control); e == nil || lease != nil {
			t.Fatal("navigation granted credential DOM access")
		}
		if history() != before || reads.Load() != beforeReads || private.fills != fills || private.submits != submits {
			t.Fatal("ordinary navigation changed private history/values")
		}
		if _, err = h.vaultExposure.AcquireExposureContext(bound); !errors.Is(err, vault.ErrDeliveryProtected) {
			t.Fatal("navigation cleared private gate", err)
		}
	}})
}
