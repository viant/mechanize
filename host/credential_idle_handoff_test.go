package host

import (
	"context"
	"github.com/viant/mechanize/auth"
	"github.com/viant/mechanize/backend/chrome"
	"github.com/viant/mechanize/data"
	"github.com/viant/mechanize/engine/durable"
	integration "github.com/viant/mechanize/integration/endly"
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

// Host, consent, Vault lease transitions and Datly are real. Only browser privacy
// qualification/absence is supplied by this inert fixture; no OS/page is touched.
func TestIdleConnectedControllerSourceHandoffPreservesReceipts(t *testing.T) {
	for _, mode := range []string{"privacyReady", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := "known"
			if mode == "unknown" {
				fixtureMode = "unknown"
			}
			credentialHostFixtureFlow(t, fixtureMode, credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				if _, e := h.CredentialApply(ctx, p, ref); e != nil && mode != "unknown" {
					t.Fatal(e)
				}
				old := f.session
				if mode == "privacyReady" {
					if _, e := h.CredentialSubmit(ctx, p, ref); e != nil {
						t.Fatal(e)
					}
					original := auth.WithConsentBinding(ctx, old.consent)
					next := old.binding
					next.DocumentID = "redacted-successor"
					next.NavigationID = strings.Repeat("b", 64)
					binding, lease, e := old.protected.TransitionDOM(original, old.binding, func(context.Context) (vault.Binding, error) { return next, nil })
					if e != nil {
						t.Fatal(e)
					}
					old.binding, old.protected = binding, lease
					old.dom = &credentialDOMState{}
					old.state = "privacyReady"
				}
				beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				fills, submits, admissions, vaultReads := f.fills, f.submits, f.admissions, reads.Load()
				f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error {
					if c.Value(handoffProcessPinKey{}) == nil {
						t.Fatal("source proof lost request-scoped process pin")
					}
					actor, _ := auth.FromContext(c)
					if actor.ClientID == p.ClientID {
						t.Fatal("handoff impersonated original client")
					}
					return c.Err()
				}
				backend := &idleHandoffBrowserFixture{credentialBrowserFixture: f}
				h.credentials.browserFixture = backend
				result, successor, newSession := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				if result.State != "awaitingPreflight" {
					t.Fatal("idle connected previous preparation remains globally held", result.AttentionCode)
				}
				afterPrep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if afterPrep.ProtectionState != "closed" || afterPrep.Revision != beforePrep.Revision+1 || len(after) != len(before) {
					t.Fatal("handoff removed original history")
				}
				for i, row := range after {
					original := before[i]
					row.ProtectionState, row.Revision, row.UpdatedAt = original.ProtectionState, original.Revision, original.UpdatedAt
					if row != original {
						t.Fatal("handoff rewrote immutable outcome")
					}
				}
				if f.fills != fills || f.submits != submits || f.admissions != admissions {
					t.Fatal("handoff replayed an input")
				}
				// Fresh Prepare may select a saved record; protection cleanup itself cannot
				// consume credentials or transfer the old selection/DOM capability.
				selectionReads := reads.Load() - vaultReads
				baseline := reads.Load()
				fresh, _, _ := prepareForeignLifecycleFixture(t, h, p, input, successor.ClientID)
				if fresh.State != "awaitingPreflight" || selectionReads <= 0 || reads.Load()-baseline != selectionReads {
					t.Fatalf("handoff/fresh selection key-read deltas differ: %d/%d", selectionReads, reads.Load()-baseline)
				}
				if mode == "privacyReady" {
					oldCtx := auth.WithConsentBinding(ctx, old.consent)
					if old.protected.VerifyDOM(oldCtx, old.binding) == nil {
						t.Fatal("old DOM lease remains usable")
					}
				}
				if old.done.Err() == nil || old.dom != nil {
					t.Fatal("original DOM capability survived handoff")
				}
				if _, e := h.CredentialApply(auth.WithPrincipal(context.Background(), successor), successor, gateway.CredentialRefInput{SessionID: newSession, PreparationID: ref.PreparationID}); e == nil {
					t.Fatal("successor inherited original private delivery")
				}
			}})
		})
	}
}

type idleHandoffBrowserFixture struct {
	*credentialBrowserFixture
	busy bool
}

func (f *idleHandoffBrowserFixture) VerifyCredentialSourceIdle(ctx context.Context, p auth.Principal) error {
	if f.busy {
		return chrome.ErrCredentialSourceInputBusy
	}
	return ctx.Err()
}
func (f *idleHandoffBrowserFixture) VerifyControllerOwnerAbsent(context.Context, auth.Principal, string) error {
	return errOtherCredentialScopeHeld
}

type handoffProcessPinKey struct{}

func (f *idleHandoffBrowserFixture) PinCredentialScopeProcesses(ctx context.Context, p auth.Principal, sources []chrome.CredentialProtectionScope) (context.Context, func(context.Context) error, error) {
	actual, _ := auth.FromContext(ctx)
	if actual.ClientID != p.ClientID || actual.ClientID == f.session.actor.ClientID || len(sources) == 0 {
		f.t.Fatal("process pin changed actual successor actor")
	}
	pinned := context.WithValue(ctx, handoffProcessPinKey{}, true)
	return pinned, func(c context.Context) error {
		if c.Value(handoffProcessPinKey{}) != true {
			return errPrivateCredential
		}
		return c.Err()
	}, nil
}

func TestIdleSourceHandoffRefusesActiveInputAndPresentSource(t *testing.T) {
	for _, kind := range []string{"activeInput", "presentSource", "cancelled", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
				if _, e := h.CredentialApply(ctx, p, ref); e != nil {
					t.Fatal(e)
				}
				beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				baseline := reads.Load()
				fills, submits := f.fills, f.submits
				f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error {
					switch kind {
					case "presentSource":
						return chrome.ErrCredentialSourcePresent
					case "cancelled":
						return context.Canceled
					case "revoked":
						return auth.ErrUnauthorized
					}
					return c.Err()
				}
				h.credentials.browserFixture = &idleHandoffBrowserFixture{credentialBrowserFixture: f, busy: kind == "activeInput"}
				result, _, _ := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
				afterPrep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
				if result.State != "needsNativeAction" || beforePrep != afterPrep || !reflect.DeepEqual(before, after) || reads.Load() != baseline || fills != f.fills || submits != f.submits || f.session.done.Err() != nil {
					t.Fatal("refused cleanup changed protection/input/selection")
				}
				if kind == "activeInput" && result.AttentionCode != "scopePreflightBusy" || kind == "presentSource" && result.AttentionCode != "scopeSourcePresent" {
					t.Fatal("finite refusal cause lost", result.AttentionCode)
				}
			}})
		})
	}
}

func TestIdleHandoffRetriesAfterParentCASWithoutRewritingReceipts(t *testing.T) {
	credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		if _, e := h.CredentialApply(ctx, p, ref); e != nil {
			t.Fatal(e)
		}
		beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error { return c.Err() }
		f.scopeRetire = func(c context.Context, s chrome.CredentialProtectionScope) error {
			rows := data.CredentialSourceCleanupAttempts(c)
			if len(rows) != len(before) {
				t.Fatal("real Datly complete snapshot unavailable to restart-safe retirement")
			}
			return chrome.ErrCredentialSourceInputBusy
		}
		h.credentials.browserFixture = &idleHandoffBrowserFixture{credentialBrowserFixture: f}
		first, _, _ := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
		closed, closedRows := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		if first.State != "needsNativeAction" || closed.ProtectionState != "closed" || closed.Revision != beforePrep.Revision+1 || closedRows[0].ProtectionState != "closed" {
			t.Fatal("fixture did not stop after parent CAS")
		}
		f.scopeRetire = func(c context.Context, s chrome.CredentialProtectionScope) error { return c.Err() }
		second, _, _ := prepareForeignLifecycleFixture(t, h, p, input, "controller:"+strings.Repeat("f", 64))
		final, finalRows := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		if second.State != "awaitingPreflight" || final != closed || !reflect.DeepEqual(finalRows, closedRows) {
			t.Fatal("finalized cleanup could not retry without rewriting outcomes", second.AttentionCode)
		}
	}})
}

func TestClosingSessionCannotInitiateForeignIdleHandoff(t *testing.T) {
	credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{clientID: "controller:" + strings.Repeat("a", 64), successorClientID: "controller:" + strings.Repeat("f", 64), exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, input gateway.CredentialPrepareInput, f *credentialBrowserFixture, reads *atomic.Int64) {
		if _, e := h.CredentialApply(ctx, p, ref); e != nil {
			t.Fatal(e)
		}
		beforePrep, before := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		baseline := reads.Load()
		oldRuntime := h.Runtime
		successor := p
		successor.ClientID = "controller:" + strings.Repeat("f", 64)
		successorCtx := auth.WithPrincipal(context.Background(), successor)
		f.scopeAbsent = func(c context.Context, s chrome.CredentialProtectionScope) error { return c.Err() }
		h.credentials.browserFixture = &idleHandoffBrowserFixture{credentialBrowserFixture: f}
		called := false
		runtime, e := integration.NewWithOptions(func(context.Context, auth.Principal, model.Step, map[string]model.Value) (integration.StepResult, error) {
			t.Fatal("closing handoff executed input")
			return integration.StepResult{}, nil
		}, integration.Options{OnSessionClose: func(closing context.Context, actor auth.Principal, id string) error {
			called = true
			cleanup := &credentialSessionCleanup{host: h, namespace: actor.Namespace, client: actor.ClientID, session: id, purpose: input.Purpose, origin: input.Surface.Origin}
			cleanup.active.Store(true)
			defer cleanup.active.Store(false)
			closing = context.WithValue(closing, credentialSessionCleanupKey{}, cleanup)
			closing = auth.WithConsentBinding(closing, auth.ConsentBinding{SessionID: id, GrantID: "current", Purpose: input.Purpose})
			if h.checkCredentialSession(closing, actor, id) != nil || h.Runtime.CheckSession(closing, actor, id) == nil {
				t.Fatal("fixture closing capability did not distinguish cleanup from ordinary session")
			}
			return h.durable.WithCredentialDeliveryComponents(closing, actor, func(held context.Context, _ durable.CredentialDeliveryComponentInvoker) error {
				scopes, e := h.durable.CredentialProtectionScopes(held, actor)
				if e != nil || len(scopes) != 1 {
					t.Fatal("closing snapshot", e)
				}
				if e = h.credentials.retireIdleControllerSource(held, actor, scopes[0]); e == nil {
					t.Fatal("closing callback initiated foreign handoff")
				}
				return nil
			})
		}})
		if e != nil {
			t.Fatal(e)
		}
		h.Runtime = runtime
		defer func() { h.Runtime = oldRuntime; runtime.Shutdown(context.Background()) }()
		opened, e := runtime.Open(successorCtx, "Closing fixture")
		if e != nil {
			t.Fatal(e)
		}
		if e = runtime.Close(successorCtx, opened.SessionID); e != nil {
			t.Fatal(e)
		}
		afterPrep, after := credentialLifecycleSnapshot(t, h, ctx, p, ref.PreparationID)
		if !called || beforePrep != afterPrep || !reflect.DeepEqual(before, after) || reads.Load() != baseline || f.session.done.Err() != nil {
			t.Fatal("closing handoff changed retained authority or history")
		}
	}})
}
