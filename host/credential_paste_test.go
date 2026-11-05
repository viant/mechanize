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
	gateway "github.com/viant/mechanize/mcp"
	"github.com/viant/mechanize/model"
	"github.com/viant/mechanize/vault"
)

type privatePasteFixture struct {
	mode, field, clipboard, token string
	probes, pastes, clears        int
	guard                         func(context.Context) error
}

func (f *privatePasteFixture) CheckEmpty(c context.Context, _ vault.Binding) error {
	if f.guard(c) != nil || f.field != "" {
		return errors.New("PRIVATE-CANARY")
	}
	return nil
}
func (f *privatePasteFixture) SetProbe(context.Context, vault.Binding) error {
	f.probes++
	f.field = "x"
	return nil
}
func (f *privatePasteFixture) CheckProbe(context.Context, vault.Binding) error {
	if f.field != "x" {
		return errors.New("PRIVATE-CANARY")
	}
	return nil
}
func (f *privatePasteFixture) RemoveProbe(context.Context, vault.Binding) error {
	if f.mode == "probe" {
		return errors.New("PRIVATE-CANARY")
	}
	f.field = ""
	return nil
}
func (f *privatePasteFixture) PasteOnce(context.Context, vault.Binding) error {
	f.pastes++
	if f.mode == "unknown" {
		return errors.New("PRIVATE-CANARY")
	}
	f.field = f.clipboard
	return nil
}
func (f *privatePasteFixture) Verify(_ context.Context, _ vault.Binding, p []byte) error {
	if f.field != string(p) {
		return errors.New("PRIVATE-CANARY")
	}
	return nil
}
func (f *privatePasteFixture) Stage(_ context.Context, token string, p []byte, _ time.Time) error {
	f.token = token
	f.clipboard = string(p)
	return nil
}
func (f *privatePasteFixture) VerifyOwnership(_ context.Context, token string) error {
	if token != f.token {
		return errors.New("PRIVATE-CANARY")
	}
	return nil
}
func (f *privatePasteFixture) Clear(context.Context, string) error {
	f.clears++
	if f.mode == "cleanup" {
		return errors.New("PRIVATE-CANARY")
	}
	f.clipboard = ""
	return nil
}

func TestCredentialPasteOwnedOpaqueDurableOneShot(t *testing.T) {
	for _, mode := range []string{"ok", "unknown", "probe", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			credentialHostFixtureFlow(t, "known", credentialHostFixtureHooks{exercise: func(t *testing.T, h *Host, ctx context.Context, p auth.Principal, ref gateway.CredentialRefInput, _ gateway.CredentialPrepareInput, browser *credentialBrowserFixture, reads *atomic.Int64) {
				beforeReads := reads.Load()
				out, err := h.CredentialPaste(ctx, p, ref)
				if err != nil || out.AttentionCode != "pasteTargetUnavailable" || browser.session.state != "ready" || len(browser.session.attempts) != 0 || reads.Load() != beforeReads {
					t.Fatal("unsupported paste consumed preparation", out, err)
				}
				f := &privatePasteFixture{mode: mode}
				h.credentialPaste = &CredentialPasteOptions{Target: func(c context.Context, actor auth.Principal, surface model.Surface, a chrome.ControlAuthority, b vault.Binding, id string, guard func(context.Context) error) (vault.PasswordPasteTarget, error) {
					if id == "" || len(browser.session.attempts) != 1 || browser.session.attempts[0].DispatchState != "unknown" || actor.ClientID != p.ClientID || surface != browser.session.surface || b != browser.session.binding || guard(c) != nil {
						t.Fatal("paste bypassed durable reservation or identity")
					}
					f.guard = guard
					return f, nil
				}, Clipboard: func() vault.PasswordPasteClipboard { return f }}
				out, err = h.CredentialPaste(ctx, p, ref)
				if err != nil || out.AttentionCode != "pastePasswordStageRequired" || browser.session.state != "ready" {
					t.Fatal("nonpassword stage admitted", out, err)
				}
				// Synthetic private inspector transition; no real site/secret is used.
				browser.session.stage = "password"
				foreign := p
				foreign.ClientID = "other-client"
				if _, err = h.CredentialPaste(auth.WithPrincipal(ctx, foreign), foreign, ref); err == nil {
					t.Fatal("foreign owner admitted")
				}
				out, err = h.CredentialPaste(ctx, p, ref)
				want := "unknown"
				if mode == "ok" {
					want = "filled"
				}
				if err != nil || out.State != want || f.probes != 1 || browser.fills != 0 || browser.submits != 0 || len(browser.session.attempts) != 1 {
					t.Fatal("paste state/receipt mismatch", out, err)
				}
				if mode == "ok" && (f.field != "password-secret-canary" || f.clipboard != "" || f.clears != 1 || browser.session.attempts[0].DispatchState != "dispatched") {
					t.Fatal("private paste or cleanup not proven")
				}
				if mode == "probe" && (f.pastes != 0 || f.clears != 0 || reads.Load() != beforeReads) {
					t.Fatal("uncertain probe consumed credential")
				}
				before := f.probes + f.pastes + f.clears
				_, _ = h.CredentialPaste(ctx, p, ref)
				_, _ = h.CredentialApply(ctx, p, ref)
				if before != f.probes+f.pastes+f.clears || browser.fills != 0 {
					t.Fatal("paste or DOM fallback replayed")
				}
				wire, _ := json.Marshal(out)
				if strings.Contains(string(wire), "canary") || strings.Contains(string(wire), "CANARY") {
					t.Fatal("private output leaked")
				}
			}})
		})
	}
}
